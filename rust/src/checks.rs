//! All individual checks, for system hardware and more
#![allow(unused_imports)] /// just for convenience
use crate::colors::*;
use crate::netinspect::*;
use crate::parser::*;
use crate::syssec::*;
use crate::freebsd::kld::{VM_LOADAVG, loadavg, DIOCGMEDIASIZE, kldstat, kld_file_stat,
    KLD_FILE_STAT_SIZE, kldnext, kldload};
use libc::{gid_t, mode_t, off_t, uid_t};
use std::fs;
use std::io::BufRead;
use std::os::raw::c_ulong;
use std::os::unix::fs::MetadataExt;
use std::process::Command;


//system related
pub fn syssec_check_information(s: &mut Syssec)
{
    check_start("System Information");
    s.add_result("System", "CPU", &format!("{} cores: {}",s.ncpu, s.cpu_model),
        Severity::Info, Status::Pass, None);
    s.add_result("System", "Memory", &format!("{} MB total", s.physmem / (1024*1024)),
         Severity::Info, Status::Pass, None);

    let uptime = s.timestamp - s.boot_time;

    let up = format!("{} days, {:02}:{:02}:{:02}",
        uptime / 86400, (uptime % 86400) / 3600, (uptime % 3600) / 60, uptime % 60);
    s.add_result("System", "Uptime", &up, Severity::Info, Status::Pass, None);

    //loadavg via sysctl
    let mut mib: [libc::c_int; 2] = [libc::CTL_VM, VM_LOADAVG];
    let mut load: loadavg = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<loadavg>() as libc::size_t;
    let r = unsafe {
        libc::sysctl(mib.as_mut_ptr(), 2,
            &mut load as *mut _ as *mut libc::c_void,
            &mut len, std::ptr::null_mut(), 0)
    };

    if r == 0 && load.fscale != 0 {
        let l1 = load.ldavg[0] as f64 / load.fscale as f64;
        let l5 = load.ldavg[1] as f64 / load.fscale as f64;
        let l15 = load.ldavg[2] as f64 / load.fscale as f64;
        let buf = format!("{:.2}, {:.2}, {:.2}", l1, l5, l15);
        let (status, sev, rec) = if s.ncpu > 0 && l1 > s.ncpu as f64 * 1.5 {
            (Status::Warn, Severity::Warning, Some("High load - check running processes"))
        } else {
            (Status::Pass, Severity::Info, None)
        };
        s.add_result("System", "Load Average", &buf, sev, status, rec);
    }
}

// processes

pub fn syssec_check_processes(s: &mut Syssec)
{
    check_start("Process Information");

    let mut mib: [libc::c_int; 4] = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ALL, 0];
    let mut len: libc::size_t = 0;
    let r = unsafe {
        libc::sysctl(mib.as_mut_ptr(), 4, std::ptr::null_mut(), &mut len, std::ptr::null_mut(), 0)
    };

    if r != 0 {
        s.add_result("Processes", "Process Scan", "Failed to read process list",
            Severity::Warning, Status::Warn, Some("Check Permissions"));
        return;
    }

    let count = len / std::mem::size_of::<libc::kinfo_proc>();
    let mut buf: Vec<libc::kinfo_proc> = vec![unsafe { std::mem::zeroed() }; count];
    let r = unsafe {
        libc::sysctl(mib.as_mut_ptr(), 4, buf.as_mut_ptr() as *mut libc::c_void, &mut len, std::ptr::null_mut(), 0)
    };

    let mut zombies = 0; let mut running = 0; let mut sleeping = 0;
    for p in &buf {
        match p.ki_stat as u8 as char {
            'Z' => zombies += 1,
            'R' => running += 1,
            'S' => sleeping += 1,
            _ => {}
        }
    }
    let msg = format!("{} total ({} running, {} sleeping, {} zombie)",
        count, running, sleeping, zombies);

    let (status, sev, rec) = if zombies > 10 {
        (Status::Warn, Severity::Warning, Some("Many zombie processes - check parent processes"))
    } else if count > 500 {
        (Status::Warn, Severity::Warning, Some("High process count - check for runaway processes"))
    } else {
        (Status::Pass, Severity::Info, None)
    };

    s.add_result("Processes", "Process Count", &msg, sev, status, rec);
}

// user-related
pub fn syssec_check_users(s: &mut Syssec) {
    check_start("User Accounts");

    let mut total = 0; let mut uid0 = 0; let mut valid_shell = 0;
    let mut bad_users: Vec<String> = Vec::new();
    let mut seen_uids: Vec<uid_t> = Vec::new();
    let mut duplicates = 0;

    unsafe {
        libc::setpwent();
        loop {
            let pw = libc::getpwent();
            if pw.is_null() { break; }
            let pw = &*pw;
            total += 1;

            let name = std::ffi::CStr::from_ptr(pw.pw_name).to_string_lossy().into_owned();
            let shell = std::ffi::CStr::from_ptr(pw.pw_shell).to_string_lossy().into_owned();

            if pw.pw_uid == 0 && name != "root" {
                uid0 += 1;
                bad_users.push(name);
            }
            if shell != "/sbin/nologin" && shell != "/usr/sbin/nologin" && shell != "/bin/false" { valid_shell += 1; }
            if pw.pw_uid != 0 && seen_uids.contains(&pw.pw_uid){
                duplicates += 1;
            } else {
                seen_uids.push(pw.pw_uid);
            }
        }
        libc::endpwent();
    }

    s.add_result("Users", "User Accounts",
        &format!("{} users ({} with shell)", total, valid_shell),
        Severity::Info, Status::Pass, None);

    if uid0 > 0 {
        s.add_result("Users", "UID 0 Users",
            &format!("Found {} additional UID 0: {}", uid0, bad_users.join(", ")),
            Severity::Critical, Status::Fail, Some("Remove additional UID 0 users immediately"));
    } else {
        s.add_result("Users", "UID 0 Users", "Only root as UID 0", Severity::Info, Status::Pass, None);
    }

    if duplicates > 0 {
        s.add_result("Users", "Duplicate UIDs", &format!("{} duplicate UIDs found", duplicates),
        Severity::Warning, Status::Warn, Some("Each user should have a unique UID"));
    }
}

//filesystems

pub fn syssec_check_filesystem(s: &mut Syssec) {
    let files: &[(&str, mode_t, &str, bool)] = &[
        ("/etc/passwd",        0o644, "Passwd file",   false),
        ("/etc/master.passwd", 0o600, "Master passwd", true),
        ("/etc/group",         0o644, "Group file",    false),
        ("/etc/sudoers",       0o440, "Sudoers file",  true),
    ];

    check_start("Critical Filesystem Files");

    for (path, expected, name, critical) in files {
        match fs::symlink_metadata(path) {
            Err(_) => {
                s.add_result("Filesystem", name,
                             &format!("{} does not exist", path),
                             if *critical { Severity::Critical } else { Severity::Warning },
                             Status::Fail,
                             Some("File should exist with proper permissions"));
            }
            Ok(md) => {
                let mode = (md.mode() & 0o777) as u32;
                let mut buf = format!("Permissions: {:03o}", mode);
                let mut status = Status::Pass;
                let mut sev = Severity::Info;
                let mut rec: Option<&str> = None;

                if mode != *expected as u32 {
                    if md.mode() & libc::S_IWOTH as u32 != 0 {
                        status = Status::Fail;
                        sev = if *critical { Severity::Critical } else { Severity::Warning };
                        buf = format!("WORLD-WRITABLE ({:03o})", mode);
                        rec = Some("Remove world-writable permission immediately");
                    } else {
                        status = Status::Warn;
                        sev = Severity::Warning;
                        rec = Some("Check file permissions");
                    }
                }
                s.add_result("Filesystem", name, &buf, sev, status, rec);
            }
        }
    }

    // Temp dirs
    check_start("Temporary Directories");
    for dir in ["/tmp", "/var/tmp", "/usr/tmp"] {
        if let Ok(md) = fs::symlink_metadata(dir) {
            if md.is_dir() {
                if md.mode() & libc::S_ISVTX as u32 != 0 {
                    s.add_result("Filesystem", dir,
                                 &format!("{} has sticky bit", dir),
                                 Severity::Info, Status::Pass, None);
                } else if md.mode() & libc::S_IWOTH as u32 != 0 {
                    s.add_result("Filesystem", dir,
                                 &format!("{} world-writable, no sticky bit!", dir),
                                 Severity::Critical, Status::Fail,
                                 Some("Add sticky bit: chmod +t"));
                } else {
                    s.add_result("Filesystem", dir,
                                 &format!("{} ok", dir),
                                 Severity::Info, Status::Pass, None);
                }
            }
        }
    }
}

//disks

pub fn syssec_check_disks(s: &mut Syssec) {
    check_start("Disk Usage");

    if let Ok(out) = Command::new("df").arg("-h").output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 6 { continue; }
            let cap_str = f[4].trim_end_matches('%');
            let cap: i32 = cap_str.parse().unwrap_or(-1);
            let (status, sev, rec) = if cap >= 95 {
                (Status::Fail, Severity::Critical, Some("Disk almost full - free space immediately"))
            } else if cap >= 80 {
                (Status::Warn, Severity::Warning, Some("Disk getting full - monitor usage"))
            } else {
                (Status::Pass, Severity::Info, None)
            };
            s.add_result("Disks", f[5],
                         &format!("{}: {} used of {} ({}%)", f[5], f[2], f[1], cap),
                         sev, status, rec);
        }
    }

    check_start("Physical Disks");
    if let Ok(entries) = fs::read_dir("/dev") {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let is_disk = name.starts_with("ada") || name.starts_with("da") ||
                name.starts_with("nvd") || name.starts_with("mmcsd");
            if !is_disk { continue; }

            let path = format!("/dev/{}", name);
            let md = match fs::symlink_metadata(&path) { Ok(m) => m, Err(_) => continue };
            if md.mode() & libc::S_IFMT as u32 != libc::S_IFCHR as u32 { continue; }

            // try to get media size via ioctl DIOCGMEDIASIZE
            let cpath = std::ffi::CString::new(path.clone()).unwrap();
            let fd = unsafe { libc::open(cpath.as_ptr(), libc::O_RDONLY) };
            if fd >= 0 {
                let mut media_size: off_t = 0;
                let r = unsafe { libc::ioctl(fd, DIOCGMEDIASIZE as libc::c_long as c_ulong, &mut media_size) };
                let msg = if r == 0 {
                    format!("{} MB", media_size / (1024 * 1024))
                } else {
                    "unknown size".to_string()
                };
                s.add_result("Disks", &name, &msg, Severity::Info, Status::Pass, None);
                unsafe { libc::close(fd); }
            }
        }
    }

    check_start("Swap");
    if let Ok(out) = Command::new("swapinfo").arg("-m").output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 { continue; }
            let device = f[0];
            let total: i32 = f.get(1).and_then(|x| x.parse().ok()).unwrap_or(0);
            let used: i32 = f.get(2).and_then(|x| x.parse().ok()).unwrap_or(0);
            let percent: i32 = f.get(4).and_then(|x| x.trim_end_matches('%').parse().ok())
                .unwrap_or(0);
            let (status, sev, rec) = if percent >= 90 {
                (Status::Fail, Severity::Critical, Some("Swap nearly full - add more swap"))
            } else if percent >= 50 {
                (Status::Warn, Severity::Warning, Some("Swap usage moderate - monitor"))
            } else {
                (Status::Pass, Severity::Info, None)
            };
            s.add_result("Disks", device,
                         &format!("{}: {} used of {} MB ({}%)", device, used, total, percent),
                         sev, status, rec);
        }
    }
}

//dev

pub fn syssec_check_dev(s: &mut Syssec) {
    check_start("Device Files (/dev)");
    let mut total = 0; let mut char_devs = 0; let mut block_devs = 0;
    let mut world_writable = 0; let mut symlinks = 0;
    let mut suspicious_list: Vec<String> = Vec::new();

    let entries = match fs::read_dir("/dev") {
        Ok(e) => e,
        Err(_) => {
            s.add_result("Devices", "/dev", "Cannot open /dev",
                         Severity::Warning, Status::Warn, None);
            return;
        }
    };

    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') { continue; }
        let path = format!("/dev/{}", name);
        let md = match fs::symlink_metadata(&path) { Ok(m) => m, Err(_) => continue };
        total += 1;
        let ft = md.mode() & libc::S_IFMT as u32;
        if ft == libc::S_IFCHR as u32 { char_devs += 1; }
        else if ft == libc::S_IFBLK as u32 { block_devs += 1; }
        else if ft == libc::S_IFLNK as u32 { symlinks += 1; }
        if (ft == libc::S_IFCHR as u32 || ft == libc::S_IFBLK as u32) && md.mode() & libc::S_IWOTH as u32 != 0 {
            world_writable += 1;
            suspicious_list.push(name);
        }
    }

    s.add_result("Devices", "/dev Summary",
                 &format!("{} devices ({} char, {} block, {} symlinks)",
                          total, char_devs, block_devs, symlinks),
                 Severity::Info, Status::Pass, None);

    if world_writable > 0 {
        s.add_result("Devices", "World-Writable",
                     &format!("{} world-writable devices: {}",
                              world_writable, suspicious_list.join(", ")),
                     Severity::Warning, Status::Warn,
                     Some("Review world-writable device nodes"));
    } else {
        s.add_result("Devices", "World-Writable",
                     "No world-writable device nodes",
                     Severity::Info, Status::Pass, None);
    }

    check_start("Essential Devices");
    for req in ["/dev/null","/dev/zero","/dev/random","/dev/urandom","/dev/console"] {
        if file_exists(req) {
            s.add_result("Devices", req, "present", Severity::Info, Status::Pass, None);
        } else {
            s.add_result("Devices", req, &format!("{} missing!", req),
                         Severity::Warning, Status::Warn,
                         Some("Essential device missing"));
        }
    }
}

//sys

pub fn syssec_check_sys(s: &mut Syssec) {
    check_start("Sysfs (/sys)");
    if !file_exists("/sys") {
        s.add_result("Sysfs", "/sys", "Not mounted (expected on FreeBSD)",
                     Severity::Info, Status::Pass, None);
        return;
    }
    for (path, label, unit) in [("/sys/devices", "/sys/devices", "devices"),
        ("/sys/class",   "/sys/class",   "classes"),
        ("/sys/module",  "/sys/module",  "modules")] {
        if !file_exists(path) { continue; }
        check_progress(format!("scanning {}...", path));
        if let Ok(entries) = fs::read_dir(path) {
            let mut count = 0;
            for e in entries.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if n.starts_with('.') { continue; }
                count += 1;
                if path == "/sys/module" {
                    println!("{}      module: {}{}", DIM, n, RESET);
                }
            }
            s.add_result("Sysfs", label,
                         &format!("{} {}", count, unit),
                         Severity::Info, Status::Pass, None);
        }
    }
}

//TTY
pub fn syssec_check_ttys(s: &mut Syssec) {
    check_start("TTY Devices (/dev/tty*)");
    let mut total = 0; let mut active = 0; let mut suspicious = 0;
    let mut suspicious_list: Vec<String> = Vec::new();

    let entries = match fs::read_dir("/dev") {
        Ok(e) => e,
        Err(_) => return,
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("tty") || name.len() <= 3 { continue; }
        let path = format!("/dev/{}", name);
        let md = match fs::metadata(&path) { Ok(m) => m, Err(_) => continue };
        if md.mode() & libc::S_IFMT as u32 != libc::S_IFCHR as u32 { continue; }
        total += 1;

        // "active" heuristic via `who`
        let who_out = Command::new("who").output();
        let is_active = who_out.as_ref().map(|o| {
            let t = String::from_utf8_lossy(&o.stdout);
            t.lines().any(|l| l.contains(&name))
        }).unwrap_or(false);

        if is_active {
            active += 1;
            check_item(&name, Status::Pass, "active, login present");
        } else {
            if s.verbose { check_item(&name, Status::Pass, "inactive"); }
        }
    }

    s.add_result("TTY", "TTY Summary",
                 &format!("{} TTYs, {} active", total, active),
                 Severity::Info, Status::Pass, None);
    if suspicious > 0 {
        s.add_result("TTY", "Suspicious TTYs",
                     &format!("{} suspicious: {}", suspicious, suspicious_list.join(", ")),
                     Severity::Warning, Status::Warn,
                     Some("Investigate TTYs without login sessions"));
    }
}

//networking
pub fn syssec_check_network(s: &mut Syssec) {
    check_start("Network");

    if let Ok(out) = Command::new("sh").arg("-c")
        .arg("sockstat -4 -l 2>/dev/null | grep -v '^USER' | wc -l").output() {
        let ports: i32 = String::from_utf8_lossy(&out.stdout).trim().parse().unwrap_or(0);
        let (status, sev, rec) = if ports > 20 {
            (Status::Warn, Severity::Warning,
             Some("Many listening ports - review with 'sockstat -4 -l'"))
        } else {
            (Status::Pass, Severity::Info, None)
        };
        s.add_result("Network", "Listening Ports",
                     &format!("{} listening TCP ports", ports), sev, status, rec);
    }

    let pf = proc_running("pfctl");
    let ipfw = proc_running("ipfw");
    if pf || ipfw {
        s.add_result("Network", "Firewall", "Firewall is running",
                     Severity::Info, Status::Pass, None);
    } else {
        s.add_result("Network", "Firewall", "No firewall detected",
                     Severity::Critical, Status::Fail,
                     Some("Enable PF: add 'pf_enable=\"YES\"' to /etc/rc.conf"));
    }

    if let Some(v) = sysctl_i32("net.inet.ip.forwarding") {
        if v != 0 {
            s.add_result("Network", "IP Forwarding",
                         "IP forwarding is ENABLED",
                         Severity::Warning, Status::Warn,
                         Some("Disable if not a router"));
        } else {
            s.add_result("Network", "IP Forwarding",
                         "IP forwarding disabled",
                         Severity::Info, Status::Pass, None);
        }
    }
}

pub fn syssec_check_network_deep(s: &mut Syssec) {
    println!();
    check_start("Deep Network Inspection");
    let mut ni = Netinspect::new(s.verbose);

    if netinspect_scan(&mut ni) != 0 {
        s.add_result("Network-Deep", "Scan", "Failed to scan network",
                     Severity::Warning, Status::Warn, None);
        return;
    }
    netinspect_aggregate_ips(&mut ni);
    netinspect_aggregate_ports(&mut ni);
    netinspect_analyze(&mut ni);

    if s.verbose {
        netinspect_print_full(&ni);
    } else {
        netinspect_print_summary(&ni);
    }
    netinspect_report(&ni, s);
}

//services

pub fn syssec_check_services(s: &mut Syssec) {
    check_start("Critical Services");
    for svc in ["syslogd","cron","sshd"] {
        let running = proc_running(svc);
        if running {
            s.add_result("Services", svc, "running",
                         Severity::Info, Status::Pass, None);
        } else {
            s.add_result("Services", svc,
                         &format!("Service '{}' is not running", svc),
                         Severity::Warning, Status::Warn,
                         Some("Check if service should be running"));
        }
    }
    check_start("Dangerous Services");
    for svc in ["telnetd","ftpd","rlogind","rshd","inetd"] {
        if proc_running(svc) {
            s.add_result("Services", svc,
                         &format!("Insecure service '{}' running!", svc),
                         Severity::Critical, Status::Fail,
                         Some("Disable immediately - insecure"));
        } else {
            s.add_result("Services", svc, "not running",
                         Severity::Info, Status::Pass, None);
        }
    }
}

//security
pub fn syssec_check_security(s: &mut Syssec) {
    check_start("Kernel Security Settings");

    if let Some(v) = sysctl_i32("kern.securelevel") {
        let (status, sev, rec) = if v == 0 {
            (Status::Warn, Severity::Warning,
             Some("Set kern.securelevel=1 in /etc/sysctl.conf"))
        } else {
            (Status::Pass, Severity::Info, None)
        };
        s.add_result("Security", "Securelevel",
                     &format!("Securelevel: {}", v), sev, status, rec);
    }

    if let Some(v) = sysctl_i32("kern.elf64.aslr.enable") {
        if v != 0 {
            s.add_result("Security", "ASLR (64-bit)", "enabled",
                         Severity::Info, Status::Pass, None);
        } else {
            s.add_result("Security", "ASLR (64-bit)", "disabled",
                         Severity::Warning, Status::Warn,
                         Some("Enable: kern.elf64.aslr.enable=1"));
        }
    }

    check_start("Kernel Modules");
    let mut total = 0;
    let mut hidden = 0;
    let mut fileid = unsafe { kldnext(0) };
    while fileid > 0 {
        let mut kfs: kld_file_stat = unsafe { std::mem::zeroed() };
        kfs.version = KLD_FILE_STAT_SIZE as i32;
        let r = unsafe { kldstat(fileid, &mut kfs) };
        if r == 0 {
            total += 1;
            let name = unsafe { std::ffi::CStr::from_ptr(kfs.name.as_ptr()) }
                .to_string_lossy().into_owned();
            let p1 = format!("/boot/kernel/{}.ko", name);
            let p2 = format!("/boot/modules/{}.ko", name);
            if !file_exists(&p1) && !file_exists(&p2) {
                hidden += 1;
                check_item(&name, Status::Fail, "NOT in filesystem (suspicious!)");
            } else if s.verbose {
                check_item(&name, Status::Pass, "loaded");
            }
        }
        fileid = unsafe { kldnext(fileid) };
    }
    s.add_result("Security", "Module Count",
                 &format!("{} modules loaded", total),
                 Severity::Info, Status::Pass, None);
    if hidden > 0 {
        s.add_result("Security", "Hidden Modules",
                     &format!("{} modules loaded but NOT in filesystem", hidden),
                     Severity::Critical, Status::Fail,
                     Some("Investigate hidden modules - possible rootkit"));
    } else {
        s.add_result("Security", "Module Files",
                     "All loaded modules found in filesystem",
                     Severity::Info, Status::Pass, None);
    }
}

//ssh
pub fn syssec_check_ssh(s: &mut Syssec) {
    check_start("SSH Configuration");
    let contents = match fs::read_to_string("/etc/ssh/sshd_config") {
        Ok(c) => c,
        Err(_) => {
            s.add_result("SSH", "Config", "Cannot read /etc/ssh/sshd_config",
                         Severity::Info, Status::Unknown,
                         Some("Ensure SSH is configured"));
            return;
        }
    };
    let mut permit_root = false;
    let mut password_auth = false;
    let mut x11_forward = false;
    for line in contents.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') { continue; }
        let lower = t.to_ascii_lowercase();
        if lower.starts_with("permitrootlogin") {
            if lower.contains("yes") &&
                !lower.contains("without-password") &&
                !lower.contains("prohibit-password") {
                permit_root = true;
            }
        }
        if lower.starts_with("passwordauthentication") && lower.contains("yes") {
            password_auth = true;
        }
        if lower.starts_with("x11forwarding") && lower.contains("yes") {
            x11_forward = true;
        }
    }

    if permit_root {
        s.add_result("SSH", "Root Login", "PermitRootLogin is enabled",
                     Severity::Critical, Status::Fail,
                     Some("Set 'PermitRootLogin no'"));
    } else {
        s.add_result("SSH", "Root Login", "Root login disabled",
                     Severity::Info, Status::Pass, None);
    }
    if password_auth {
        s.add_result("SSH", "Password Auth", "Password auth enabled",
                     Severity::Warning, Status::Warn,
                     Some("Use key-based auth only"));
    } else {
        s.add_result("SSH", "Password Auth", "Password auth disabled",
                     Severity::Info, Status::Pass, None);
    }
    if x11_forward {
        s.add_result("SSH", "X11 Forwarding", "X11 forwarding enabled",
                     Severity::Warning, Status::Warn,
                     Some("Disable X11 forwarding unless needed"));
    }
}

pub fn syssec_check_suid(s: &mut Syssec) {
    check_start("SUID/SGID Binaries");
    let known = [
        "/usr/bin/su","/usr/bin/sudo","/usr/bin/passwd",
        "/usr/bin/crontab","/usr/bin/at","/usr/bin/chsh",
        "/usr/bin/chfn","/usr/bin/newgrp","/usr/bin/lock",
        "/usr/bin/login","/usr/sbin/ping","/usr/sbin/traceroute",
        "/usr/local/bin/sudo","/usr/local/bin/su",
    ];

    let out = match Command::new("sh").arg("-c")
        .arg("find / -type f \\( -perm -4000 -o -perm -2000 \\) 2>/dev/null")
        .output() {
        Ok(o) => o, Err(_) => return,
    };
    let mut count = 0; let mut suspicious = 0;
    let mut suspicious_list: Vec<String> = Vec::new();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if line.is_empty() { continue; }
        count += 1;
        let is_known = known.iter().any(|k| *k == line);
        if !is_known {
            suspicious += 1;
            let base = line.rsplit('/').next().unwrap_or(line);
            if s.verbose { check_item(base, Status::Warn, "unexpected SUID/SGID"); }
            suspicious_list.push(base.to_string());
        } else if s.verbose {
            check_item(line, Status::Pass, "expected");
        }
    }
    if suspicious > 0 {
        s.add_result("SUID", "Unexpected Binaries",
                     &format!("{} unexpected: {}", suspicious, suspicious_list.join(", ")),
                     Severity::Warning, Status::Warn,
                     Some("Review unexpected SUID/SGID binaries"));
    } else {
        s.add_result("SUID", "Binaries",
                     &format!("{} SUID/SGID binaries found", count),
                     Severity::Info, Status::Pass, None);
    }
}

pub fn syssec_check_logs(s: &mut Syssec) {
    check_start("System Logs");
    let mut found = 0;
    for log in ["/var/log/messages","/var/log/auth.log","/var/log/secure",
        "/var/log/maillog","/var/log/cron"] {
        if let Ok(md) = fs::metadata(log) {
            s.add_result("Logs", log, &format!("{} bytes", md.len()),
                         Severity::Info, Status::Pass, None);
            found += 1;
        } else if s.verbose {
            check_item(log, Status::Pass, "missing");
        }
    }
    if found == 0 {
        s.add_result("Logs", "System Logs", "No standard logs found",
                     Severity::Warning, Status::Warn,
                     Some("Check syslogd configuration"));
    }
}

// ---- Updates ----

pub fn syssec_check_updates(s: &mut Syssec) {
    check_start("System Updates");
    if file_exists("/usr/sbin/freebsd-update") {
        s.add_result("Updates", "freebsd-update", "installed",
                     Severity::Info, Status::Pass,
                     Some("Run: freebsd-update fetch install"));
    } else {
        s.add_result("Updates", "freebsd-update", "not installed",
                     Severity::Warning, Status::Warn,
                     Some("Consider installing freebsd-update"));
    }
    if file_exists("/usr/sbin/pkg") {
        s.add_result("Updates", "pkg", "installed",
                     Severity::Info, Status::Pass, Some("Run: pkg upgrade"));
    }
}

// ---- Deep parse ----

pub fn syssec_check_deep_parse(s: &mut Syssec) {
    println!();
    check_start("Deep Parse: /dev");
    let mut dev = ParseResult::default();
    parser_parse_dev(&mut dev, s.verbose);
    parser_print_result("/dev", &dev);

    println!();
    check_start("Deep Parse: /sys");
    let mut sysr = ParseResult::default();
    parser_parse_sys(&mut sysr, s.verbose);
    parser_print_result("/sys", &sysr);

    println!();
    check_start("Deep Parse: /bin tree");
    let mut binr = ParseResult::default();
    parser_parse_bin(&mut binr, s.verbose);
    parser_print_result("/bin tree", &binr);

    println!();
    check_start("Binary Integrity Check");
    let mut integ = BinaryIntegrity::default();
    parser_integrity_check_standard(&mut integ, s.verbose);
    parser_integrity_report(s, &integ);
}

// ---- Main scan ----

pub fn syssec_scan(s: &mut Syssec, skip_network: bool) {
    syssec_log!(LogLevel::Info, "Starting security scan on {}", s.hostname);
    println!();

    //syssec_check_sys(s);        println!();
    syssec_check_processes(s);     println!();
    syssec_check_users(s);         println!();
    syssec_check_filesystem(s);    println!();
    syssec_check_disks(s);         println!();
    syssec_check_dev(s);           println!();
    syssec_check_sys(s);           println!();
    syssec_check_ttys(s);          println!();
    syssec_check_services(s);      println!();
    syssec_check_security(s);      println!();
    syssec_check_ssh(s);           println!();
    syssec_check_suid(s);          println!();
    syssec_check_logs(s);          println!();
    syssec_check_updates(s);       println!();
    syssec_check_deep_parse(s);    println!();

    if !skip_network {
        syssec_check_network(s);
        syssec_check_network_deep(s);
    }

    syssec_log!(LogLevel::Info,
        "Scan complete: {} checks ({} passed, {} warnings, {} failed)",
        s.results.len(), s.passed, s.warnings, s.failures);
}