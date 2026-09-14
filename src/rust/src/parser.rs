//! Tree parser and binary integrity checker
//!
use crate::colors::*;
use crate::syssec::*;
use libc::{mode_t, S_IFBLK, S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFREG, S_IFSOCK };
use std::fs;
use std::ffi::CStr;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub const PARSER_MAX_ENTRIES: usize = 4096;
pub const PARSER_MAX_PATH: usize = 512;
pub const PARSER_MAX_HASH: usize = 65;

#[derive(Clone, Default)]
pub struct BinaryCheck {
    pub name: String,
    pub path: String,
    pub expected_hash: String,
    pub actual_hash: String,
    pub exists: bool,
    pub hash_match: bool,
    pub is_setuid: bool,
    pub is_setgid: bool,
    pub is_world_writable: bool,
    pub mode: mode_t,
    pub uid: u32,
    pub gid: u32,
    pub size: i64,
}

#[derive(Default)]
pub struct BinaryIntegrity {
    pub binaries: Vec<BinaryCheck>,
    pub verified: i32,
    pub modified: i32,
    pub missing: i32,
    pub suspicious: i32,
}

#[derive(Clone, Default)]
pub struct ParsedEntry {
    pub path: String,
    pub name: String,
    pub mode: mode_t,
    pub uid: u32,
    pub gid: u32,
    pub size: i64,
    pub is_dir: bool,
    pub is_char: bool,
    pub is_block: bool,
    pub is_symlink: bool,
    pub is_fifo: bool,
    pub is_socket: bool,
    pub is_regular: bool,
    pub target: String,
    pub major: i32,
    pub minor: i32,
}

#[derive(Default)]
pub struct ParseResult {
    pub entries: Vec<ParsedEntry>,
    pub dirs: i32,
    pub files: i32,
    pub symlinks: i32,
    pub devices_char: i32,
    pub devices_block: i32,
    pub fifos: i32,
    pub sockets: i32,
    pub setuid: i32,
    pub setgid: i32,
    pub world_writable: i32,
    pub root_owned: i32,
}

impl ParseResult {
    pub fn count(&self) -> usize { self.entries.len() }
}

// Sha256 via 'sha256 -q'
pub fn compute_sha256(path: &str) -> Option<String> {
    let out = std::process::Command::new("sha256")
        .arg("-q").arg(path)
        .stderr(std::process::Stdio::null())
        .output().ok()?;
    if !out.status.success() { return None; }
    let line = String::from_utf8_lossy(&out.stdout);
    let trimmed = line.trim();
    if trimmed.len() != 64 { return None; }
    Some(trimmed.to_string())
}

//classification
fn classify(entry: &mut ParsedEntry, mode: mode_t, rdev: u64) {
    entry.is_dir    = (mode & libc::S_IFMT) == S_IFDIR;
    entry.is_char   = (mode & libc::S_IFMT) == S_IFCHR;
    entry.is_block  = (mode & libc::S_IFMT) == S_IFBLK;
    entry.is_symlink = (mode & libc::S_IFMT) == S_IFLNK;
    entry.is_fifo   = (mode & libc::S_IFMT) == S_IFIFO;
    entry.is_socket = (mode & libc::S_IFMT) == S_IFSOCK;
    entry.is_regular = (mode & libc::S_IFMT) == S_IFREG;

    if entry.is_char || entry.is_block {
        entry.major = unsafe { libc::major(rdev as libc::dev_t)} as i32;
        entry.minor = unsafe { libc::minor(rdev as libc::dev_t)} as i32;
    } else {
        entry.major = -1;
        entry.minor = -1;
    }
}

fn type_str(e: &ParsedEntry) -> &'static str {
    if e.is_dir { "DIR" }
    else if e.is_symlink { "LNK" }
    else if e.is_char { "CHR" }
    else if e.is_block { "BLK" }
    else if e.is_fifo { "FIFO" }
    else if e.is_socket { "SOCK" }
    else if e.is_regular { "FILE" }
    else { "????" }
}

fn print_indent(depth: i32) {
    for _ in 0..depth { print!(" "); }
}

fn walk_recursive(path: &str, depth: i32, max_depth: i32, verbose: bool,
            result: &mut ParseResult) -> i32 {
    if max_depth > 0 && depth > max_depth { return 0; }
    if result.entries.len() >= PARSER_MAX_ENTRIES { return 0; }

    let dir = match fs::read_dir(path){
        Ok(d) => d,
        Err(e) => {
            if verbose {
                print_indent(depth);
                println!("{} Cannot open {}: {}{}", RED, path, e, RESET);
            }
            return -1;
        }
    };

    for entry_res in dir {
        if result.entries.len() >= PARSER_MAX_ENTRIES { break; }
        let entry = match entry_res {
            Ok(e) => e,
            Err(_) => continue
        };
        let name = match entry.file_name().into_string() {
            Ok(s) => s,
            Err(_) => continue,
        };
        if name == "." || name == ".." { continue; }

        let child = format!("{}/{}", path, name);

        let md = match fs::symlink_metadata(&child) {
            Ok(m) => m,
            Err(e) => {
                if verbose {
                    print_indent(depth);
                    println!("{} {}: {}{}", RED, name, e, RESET);
                }
                continue;
            }
        };

        let mut e = ParsedEntry::default();
        e.path = child.clone();
        e.name = name.clone();
        e.mode = md.mode() as mode_t;
        e.uid = md.uid();
        e.gid = md.gid();
        e.size = md.size() as i64;
        classify(&mut e, md.mode() as mode_t, md.rdev());

        if e.is_symlink {
            if let Ok(t) = fs::read_link(&child) {
                e.target = t.to_string_lossy().to_owned().parse().unwrap();
            }
        }

        //update counters
        if e.is_dir { result.dirs += 1; }
        if e.is_regular { result.files += 1; }
        if e.is_symlink { result.symlinks += 1; }
        if e.is_char { result.devices_char += 1; }
        if e.is_block { result.devices_block += 1; }
        if e.is_fifo { result.fifos += 1; }
        if e.is_socket { result.sockets += 1; }
        if e.mode & libc::S_ISUID != 0 { result.setuid += 1; }
        if e.mode & libc::S_ISGID != 0 { result.setgid += 1; }
        if e.mode & libc::S_IWOTH != 0 { result.world_writable += 1; }
        if e.uid == 0 { result.root_owned += 1; }

        if verbose {
            let perm = mode_to_string(e.mode & 0o7777);
            let mut extra = String::new();
            if e.is_symlink && !e.target.is_empty() {
                extra = format!(" ->{}", e.target);
            } else if e.is_char || e.is_block {
                extra = format!(" [{},{}]", e.major, e.minor);
            } else if e.is_regular {
                extra = format!(" {} bytes", e.size);
            }

            let color = if e.mode & libc::S_IWOTH != 0 { RED } else if e.mode & libc::S_ISUID != 0 { MAGENTA } else if e.mode & libc::S_ISGID != 0 { YELLOW } else { RESET };

            print_indent(depth);
            println!("  {}{:<4} {} uid={} gid={} {}{}{}",
                     color, type_str(&e), perm, e.uid, e.gid, e.name, extra, RESET);
        }

        let is_dir = e.is_dir;
        result.entries.push(e);

        if is_dir {
            walk_recursive(&child, depth + 1, max_depth, verbose, result);
        }
    }
    0
}

pub fn parser_walk_dir(root: &str, max_depth: i32, verbose: bool, result: &mut ParseResult) -> i32 {
    *result = ParseResult::default();
    if verbose {
        println!("\n{}{}===========================",BOLD, CYAN);
        println!(" Parsing tree: {} (max depth: {})", root, if max_depth == 0 { -1 } else {max_depth});
        println!("============={}", RESET);
    }
    walk_recursive(root, 0, max_depth, verbose, result)
}

pub fn parser_parse_dev(result: &mut ParseResult, verbose: bool) -> i32 {
    if verbose { println!("\n{} ==== /dev/ Deep Parse ====={}", BOLD, RESET); }
    parser_walk_dir("/dev", 1, verbose, result)
}

pub fn parser_parse_sys(result: &mut ParseResult, verbose: bool) -> i32 {
    if verbose { println!("\n{}=== /sys Deep Parse ==={}", BOLD, RESET); }
    if fs::metadata("/sys").is_err() {
        if verbose {
            println!("  {} /sys not mounted (expected on FreeBSD){}", YELLOW, RESET);
        }
        *result = ParseResult::default();
        return 0;
    }
    parser_walk_dir("/sys", 3, verbose, result)
}

pub fn parser_parse_bin(result: &mut ParseResult, verbose: bool) -> i32 {
    *result = ParseResult::default();
    let dirs = ["/bin", "/sbin", "/usr/bin", "/usr/sbin"];
    if verbose { println!("\n{}=== /bin Tree Deep Parse ==={}", BOLD, RESET); }

    for d in dirs {
        if fs::metadata(d).is_err() { continue; }
        if verbose { println!("\n{}▸ {}{}", CYAN, d, RESET); }

        let mut tmp = ParseResult::default();
        parser_walk_dir(d, 1, verbose, &mut tmp);

        for e in tmp.entries {
            if result.entries.len() >= PARSER_MAX_ENTRIES { break; }
            result.entries.push(e);
        }
        result.dirs           += tmp.dirs;
        result.files          += tmp.files;
        result.symlinks       += tmp.symlinks;
        result.devices_char   += tmp.devices_char;
        result.devices_block  += tmp.devices_block;
        result.fifos          += tmp.fifos;
        result.sockets        += tmp.sockets;
        result.setuid         += tmp.setuid;
        result.setgid         += tmp.setgid;
        result.world_writable += tmp.world_writable;
        result.root_owned     += tmp.root_owned;
    }
    0
}

pub fn parser_print_result(label: &str, result: &ParseResult) {
    println!("\n{}─── {} summary ───{}", BOLD, label, RESET);
    println!("  Entries:          {}", result.entries.len());
    println!("  Directories:      {}", result.dirs);
    println!("  Regular files:    {}", result.files);
    println!("  Symlinks:         {}", result.symlinks);
    println!("  Char devices:     {}", result.devices_char);
    println!("  Block devices:    {}", result.devices_block);
    println!("  FIFOs:            {}", result.fifos);
    println!("  Sockets:          {}", result.sockets);
    println!("  Setuid:           {}", result.setuid);
    println!("  Setgid:           {}", result.setgid);
    println!("  World-writable:   {}", result.world_writable);
    println!("  Root-owned:       {}", result.root_owned);
}

struct StdBinary { name: &'static str, path: &'static str, expected: Option<&'static str> }

const STANDARD_BINARIES: &[StdBinary] = &[
    // /bin
    StdBinary{name:"cat",path:"/bin/cat",expected:None},
    StdBinary{name:"chmod",path:"/bin/chmod",expected:None},
    StdBinary{name:"chown",path:"/bin/chown",expected:None},
    StdBinary{name:"cp",path:"/bin/cp",expected:None},
    StdBinary{name:"date",path:"/bin/date",expected:None},
    StdBinary{name:"dd",path:"/bin/dd",expected:None},
    StdBinary{name:"df",path:"/bin/df",expected:None},
    StdBinary{name:"echo",path:"/bin/echo",expected:None},
    StdBinary{name:"ed",path:"/bin/ed",expected:None},
    StdBinary{name:"expr",path:"/bin/expr",expected:None},
    StdBinary{name:"getfacl",path:"/bin/getfacl",expected:None},
    StdBinary{name:"hostname",path:"/bin/hostname",expected:None},
    StdBinary{name:"kill",path:"/bin/kill",expected:None},
    StdBinary{name:"ln",path:"/bin/ln",expected:None},
    StdBinary{name:"ls",path:"/bin/ls",expected:None},
    StdBinary{name:"mkdir",path:"/bin/mkdir",expected:None},
    StdBinary{name:"mv",path:"/bin/mv",expected:None},
    StdBinary{name:"pax",path:"/bin/pax",expected:None},
    StdBinary{name:"ps",path:"/bin/ps",expected:None},
    StdBinary{name:"pwd",path:"/bin/pwd",expected:None},
    StdBinary{name:"rcp",path:"/bin/rcp",expected:None},
    StdBinary{name:"rm",path:"/bin/rm",expected:None},
    StdBinary{name:"rmdir",path:"/bin/rmdir",expected:None},
    StdBinary{name:"setfacl",path:"/bin/setfacl",expected:None},
    StdBinary{name:"sh",path:"/bin/sh",expected:None},
    StdBinary{name:"sleep",path:"/bin/sleep",expected:None},
    StdBinary{name:"stty",path:"/bin/stty",expected:None},
    StdBinary{name:"sync",path:"/bin/sync",expected:None},
    StdBinary{name:"test",path:"/bin/test",expected:None},
    StdBinary{name:"uuidgen",path:"/bin/uuidgen",expected:None},
    // /sbin
    StdBinary{name:"camcontrol",path:"/sbin/camcontrol",expected:None},
    StdBinary{name:"devfs",path:"/sbin/devfs",expected:None},
    StdBinary{name:"dmesg",path:"/sbin/dmesg",expected:None},
    StdBinary{name:"fdisk",path:"/sbin/fdisk",expected:None},
    StdBinary{name:"fsck",path:"/sbin/fsck",expected:None},
    StdBinary{name:"ifconfig",path:"/sbin/ifconfig",expected:None},
    StdBinary{name:"init",path:"/sbin/init",expected:None},
    StdBinary{name:"kldload",path:"/sbin/kldload",expected:None},
    StdBinary{name:"kldstat",path:"/sbin/kldstat",expected:None},
    StdBinary{name:"kldunload",path:"/sbin/kldunload",expected:None},
    StdBinary{name:"md5",path:"/sbin/md5",expected:None},
    StdBinary{name:"mount",path:"/sbin/mount",expected:None},
    StdBinary{name:"newfs",path:"/sbin/newfs",expected:None},
    StdBinary{name:"ping",path:"/sbin/ping",expected:None},
    StdBinary{name:"reboot",path:"/sbin/reboot",expected:None},
    StdBinary{name:"route",path:"/sbin/route",expected:None},
    StdBinary{name:"shutdown",path:"/sbin/shutdown",expected:None},
    StdBinary{name:"sha256",path:"/sbin/sha256",expected:None},
    StdBinary{name:"sysctl",path:"/sbin/sysctl",expected:None},
    StdBinary{name:"umount",path:"/sbin/umount",expected:None},
    // /usr/bin
    StdBinary{name:"awk",path:"/usr/bin/awk",expected:None},
    StdBinary{name:"basename",path:"/usr/bin/basename",expected:None},
    StdBinary{name:"bc",path:"/usr/bin/bc",expected:None},
    StdBinary{name:"cmp",path:"/usr/bin/cmp",expected:None},
    StdBinary{name:"cut",path:"/usr/bin/cut",expected:None},
    StdBinary{name:"diff",path:"/usr/bin/diff",expected:None},
    StdBinary{name:"dirname",path:"/usr/bin/dirname",expected:None},
    StdBinary{name:"du",path:"/usr/bin/du",expected:None},
    StdBinary{name:"env",path:"/usr/bin/env",expected:None},
    StdBinary{name:"expand",path:"/usr/bin/expand",expected:None},
    StdBinary{name:"file",path:"/usr/bin/file",expected:None},
    StdBinary{name:"find",path:"/usr/bin/find",expected:None},
    StdBinary{name:"finger",path:"/usr/bin/finger",expected:None},
    StdBinary{name:"ftp",path:"/usr/bin/ftp",expected:None},
    StdBinary{name:"grep",path:"/usr/bin/grep",expected:None},
    StdBinary{name:"head",path:"/usr/bin/head",expected:None},
    StdBinary{name:"id",path:"/usr/bin/id",expected:None},
    StdBinary{name:"less",path:"/usr/bin/less",expected:None},
    StdBinary{name:"logger",path:"/usr/bin/logger",expected:None},
    StdBinary{name:"login",path:"/usr/bin/login",expected:None},
    StdBinary{name:"mail",path:"/usr/bin/mail",expected:None},
    StdBinary{name:"more",path:"/usr/bin/more",expected:None},
    StdBinary{name:"netstat",path:"/usr/bin/netstat",expected:None},
    StdBinary{name:"passwd",path:"/usr/bin/passwd",expected:None},
    StdBinary{name:"printf",path:"/usr/bin/printf",expected:None},
    StdBinary{name:"sed",path:"/usr/bin/sed",expected:None},
    StdBinary{name:"sort",path:"/usr/bin/sort",expected:None},
    StdBinary{name:"ssh",path:"/usr/bin/ssh",expected:None},
    StdBinary{name:"su",path:"/usr/bin/su",expected:None},
    StdBinary{name:"sudo",path:"/usr/local/bin/sudo",expected:None},
    StdBinary{name:"tail",path:"/usr/bin/tail",expected:None},
    StdBinary{name:"tar",path:"/usr/bin/tar",expected:None},
    StdBinary{name:"tee",path:"/usr/bin/tee",expected:None},
    StdBinary{name:"telnet",path:"/usr/bin/telnet",expected:None},
    StdBinary{name:"top",path:"/usr/bin/top",expected:None},
    StdBinary{name:"tr",path:"/usr/bin/tr",expected:None},
    StdBinary{name:"uname",path:"/usr/bin/uname",expected:None},
    StdBinary{name:"uniq",path:"/usr/bin/uniq",expected:None},
    StdBinary{name:"vi",path:"/usr/bin/vi",expected:None},
    StdBinary{name:"wc",path:"/usr/bin/wc",expected:None},
    StdBinary{name:"who",path:"/usr/bin/who",expected:None},
    StdBinary{name:"whoami",path:"/usr/bin/whoami",expected:None},
    StdBinary{name:"xargs",path:"/usr/bin/xargs",expected:None},
    // /usr/sbin
    StdBinary{name:"arp",path:"/usr/sbin/arp",expected:None},
    StdBinary{name:"chown",path:"/usr/sbin/chown",expected:None},
    StdBinary{name:"cron",path:"/usr/sbin/cron",expected:None},
    StdBinary{name:"crond",path:"/usr/sbin/crond",expected:None},
    StdBinary{name:"ftpd",path:"/usr/sbin/ftpd",expected:None},
    StdBinary{name:"inetd",path:"/usr/sbin/inetd",expected:None},
    StdBinary{name:"lsof",path:"/usr/sbin/lsof",expected:None},
    StdBinary{name:"named",path:"/usr/sbin/named",expected:None},
    StdBinary{name:"newsyslog",path:"/usr/sbin/newsyslog",expected:None},
    StdBinary{name:"ntpd",path:"/usr/sbin/ntpd",expected:None},
    StdBinary{name:"pfctl",path:"/usr/sbin/pfctl",expected:None},
    StdBinary{name:"sockstat",path:"/usr/sbin/sockstat",expected:None},
    StdBinary{name:"sshd",path:"/usr/sbin/sshd",expected:None},
    StdBinary{name:"syslogd",path:"/usr/sbin/syslogd",expected:None},
    StdBinary{name:"tcpdump",path:"/usr/sbin/tcpdump",expected:None},
    StdBinary{name:"traceroute",path:"/usr/sbin/traceroute",expected:None},
];

pub fn parser_binary_verify(path: &str, expected_hash: Option<&str>,
                            check: &mut BinaryCheck) -> i32 {
    *check = BinaryCheck::default();
    let base = path.rsplit('/').next().unwrap_or(path);
    check.name = base.to_string();
    check.path = path.to_string();

    let md = match std::fs::metadata(path) {
        Ok(m) => m,
        Err(_) => { check.exists = false; return 0; }
    };

    check.exists = true;
    check.mode = md.mode() as mode_t;
    check.uid = md.uid();
    check.gid = md.gid();
    check.size = md.size() as i64;
    check.is_setuid = (md.mode() & libc::S_ISUID as u32) != 0;
    check.is_setgid = (md.mode() & libc::S_ISGID as u32) != 0;
    check.is_world_writable = (md.mode() & libc::S_IWOTH as u32) != 0;

    if md.is_file() {
        if let Some(h) = compute_sha256(path) {
            check.actual_hash = h;
        }
        if let Some(exp) = expected_hash {
            if !exp.is_empty() {
                check.expected_hash = exp.to_string();
                check.hash_match = check.actual_hash.eq_ignore_ascii_case(exp);
            } else {
                check.hash_match = true;
            }
        } else {
            check.hash_match = true;
        }
    }
    0
}

pub fn parser_integrity_check_standard(integrity: &mut BinaryIntegrity, verbose: bool) -> i32 {
    *integrity = BinaryIntegrity::default();

    println!("\n{}{}----------------------------------------", BOLD, CYAN);
    println!("  Binary Integrity Check — Standard Utilities");
    println!("===================================================={}", RESET);
    println!();

    for sb in STANDARD_BINARIES {
        if integrity.binaries.len() >= 128 { break; }

        let mut bc = BinaryCheck::default();
        parser_binary_verify(sb.path, sb.expected, &mut bc);

        let (status, note) = if !bc.exists {
            integrity.missing += 1;
            (2, "MISSING".to_string())
        } else if bc.is_world_writable {
            integrity.suspicious += 1;
            (2, "WORLD-WRITABLE".to_string())
        } else if bc.uid != 0 {
            integrity.suspicious += 1;
            (1, format!("owned by uid {}", bc.uid))
        } else if bc.mode & libc::S_IXUSR == 0 {
            integrity.suspicious += 1;
            (1, "not executable".to_string())
        } else if sb.expected.is_some() && !bc.hash_match {
            integrity.modified += 1;
            (2, "HASH MISMATCH".to_string())
        } else {
            integrity.verified += 1;
            (0, "OK".to_string())
        };

        if verbose || status != 0 {
            let (color, symbol) = match status {
                0 => (GREEN, "Y"), //Yes
                1 => (YELLOW, "W"), //Warn
                _ => (RED, "F"), //FAIL
            };
            if bc.exists {
                println!("    {}{}{} {:<15} {:<16} uid={:<4} gid={:<4} {}",
                         color, symbol, RESET, bc.name, bc.path, bc.uid, bc.gid, note);
            } else {
                println!("    {}{}{} {:<15} {:<16} {}",
                         color, symbol, RESET, bc.name, bc.path, note);
            }
        }

        integrity.binaries.push(bc);
    }

    println!();
    println!("  {}Integrity Summary:{}", BOLD, RESET);
    println!("    Checked:   {}", integrity.binaries.len());
    println!("    {}Verified:{}  {}", GREEN, RESET, integrity.verified);
    println!("    {}Modified:{}  {}", YELLOW, RESET, integrity.modified);
    println!("    {}Missing:{}   {}", RED, RESET, integrity.missing);
    println!("    {}Suspicious:{} {}", RED, RESET, integrity.suspicious);
    println!();
    0
}

pub fn parser_integrity_print(integrity: &BinaryIntegrity) {
    println!("\n{}─── Binary Integrity Report ───{}", BOLD, RESET);
    println!("  Total checked:  {}", integrity.binaries.len());
    println!("  Verified:       {}", integrity.verified);
    println!("  Modified:       {}", integrity.modified);
    println!("  Missing:        {}", integrity.missing);
    println!("  Suspicious:     {}", integrity.suspicious);
}

pub fn parser_integrity_report(s: &mut Syssec, integrity: &BinaryIntegrity) {
    let summary = format!(
        "{} checked, {} verified, {} modified, {} missing, {} suspicious",
        integrity.binaries.len(), integrity.verified,
        integrity.modified, integrity.missing, integrity.suspicious);

    let (sev, status, rec) = if integrity.missing > 0 || integrity.modified > 0 {
        (Severity::Critical, Status::Fail,
         Some("Reinstall missing or modified binaries from trusted sources"))
    } else if integrity.suspicious > 0 {
        (Severity::Warning, Status::Warn,
         Some("Review binaries with suspicious permissions"))
    } else {
        (Severity::Info, Status::Pass, None)
    };

    s.add_result("Integrity", "Standard Binaries", &summary, sev, status, rec);

    for bc in &integrity.binaries {
        if !bc.exists {
            s.add_result("Integrity", &bc.name,
                         &format!("{} is MISSING", bc.path),
                         Severity::Critical, Status::Fail,
                         Some("Reinstall from trusted source immediately"));
        } else if bc.is_world_writable {
            s.add_result("Integrity", &bc.name,
                         &format!("{} is WORLD-WRITABLE", bc.path),
                         Severity::Critical, Status::Fail,
                         Some("Remove world-writable permission immediately"));
        } else if bc.uid != 0 {
            s.add_result("Integrity", &bc.name,
                         &format!("{} owned by uid {} (not root)", bc.path, bc.uid),
                         Severity::Warning, Status::Warn,
                         Some("System binaries should be owned by root"));
        }
    }
}