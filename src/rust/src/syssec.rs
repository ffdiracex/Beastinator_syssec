//! core scanner state and result manangement for FreeBSD
//!
use crate::colors::*;
use libc::{c_char, gid_t, mode_t, off_t, uid_t};
use std::ffi::CStr;
use std::fmt;

pub const SYSSEC_VERSION: &str = "1.1.0;";
pub const MAX_RESULTS: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Info = 0,
    Warning = 1,
    Critical = 2,
}

#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum Status {
    Pass = 0,
    Warn = 1,
    Fail = 2,
    Unknown = 3,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Error = 0,
    Warning = 1,
    Info = 2,
    Debug = 3,
}

#[derive(Clone)]
pub struct Result_ {
    pub name: String,
    pub description: String,
    pub recommendation: String,
    pub category: String,
    pub severity: Severity,
    pub status: Status,
}

pub struct Syssec {
    pub results: Vec<Result_>,
    pub hostname: String,
    pub kernel: String,
    pub os_release: String,
    pub cpu_model: String,
    pub ncpu: i32,
    pub physmem: i64,
    pub boot_time: i64,
    pub timestamp: i64,
    pub passed: i32,
    pub warnings: i32,
    pub failures: i32,
    pub verbose: bool,
    pub is_root: bool,
}

impl Syssec {
    pub fn new(verbose: bool) -> Self {
        let mut s = Syssec {
            results: Vec::with_capacity(MAX_RESULTS),
            hostname: String::new(),
            kernel: String::new(),
            os_release: String::new(),
            cpu_model: String::new(),
            ncpu: 0,
            physmem: 0,
            boot_time: 0,
            timestamp: now(),
            passed: 0,
            warnings: 0,
            failures: 0,
            verbose,
            is_root: unsafe { libc::geteuid() == 0 },
        };
        s.hostname = sysctl_string("kern.hostname").unwrap_or_else(|| "unknown".into());
        s.kernel = sysctl_string("kern.version").unwrap_or_else(|| "unknown".into());
        s.os_release = sysctl_string("kern.osrelease").unwrap_or_else(|| "unknown".into());
        s.ncpu = sysctl_i32("hw.ncpu").unwrap_or(0);
        s.cpu_model = sysctl_string("hw.model").unwrap_or_default();
        s.physmem = sysctl_i64("hw.physmem").unwrap_or(0);
        s.boot_time = sysctl_i64("kern.boottime").unwrap_or(0);
        s
    }

    pub fn add_result(&mut self,
        category: &str, name: &str, desc:&str, sev: Severity, status: Status,
        rec: Option<&str>)
    {
        if self.results.len() >= MAX_RESULTS { return; }

        match status {
            Status::Pass => self.passed += 1,
            Status::Warn => self.warnings += 1,
            Status::Fail => self.failures += 1,
            _ => {}
        }

        self.results.push(Result_{
            name: name.to_string(),
            description: desc.to_string(),
            recommendation: rec.unwrap_or("").to_string(),
            category: category.to_string(),
            severity: sev,
            status
        });
        check_item(name, status, desc);
    }
}

impl Drop for Syssec {
    fn drop(&mut self) {
        //rust handles this apparently, FIXME: does it?
    }
}

//logging
use std::sync::atomic::{AtomicI32, AtomicBool, Ordering};
pub const G_LOG_LEVEL: AtomicI32 = AtomicI32::new(LogLevel::Info as i32);
pub const G_QUIET: AtomicBool = AtomicBool::new(false);

pub fn set_log_level(l: LogLevel) { G_LOG_LEVEL.store(l as i32, Ordering::SeqCst); }
pub fn set_quiet(q: bool) { G_QUIET.store(q, Ordering::SeqCst); }
pub fn quiet() -> bool { G_QUIET.load(Ordering::SeqCst) }

macro_rules!  syssec_log {
    ($level:expr, $($arg:tt)*) => {{
        let lvl = $level as i32;
        if !(crate::syssec::quiet() && lvl > crate::syssec::LogLevel::Error as i32)
          && lvl <= crate::syssec::G_LOG_LEVEL.load(std::sync::atomic::Ordering::SeqCst)
        {
            let (name, color) = match $level {
                crate::syssec::LogLevel::Error => ("ERROR", crate::colors::RED),
                crate::syssec::LogLevel::Warning => ("WARNING", crate::colors::YELLOW),
                crate::syssec::LogLevel::Info => ("INFO", crate::colors::GREEN),
                crate::syssec::LogLevel::Debug => ("DEBUG", crate::colors::CYAN),
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let tm = local_time_hms(now.try_into().unwrap());
            eprintln!("{}{} {:<7}{} {}{}{}",
                crate::colors::DIM, tm, name, crate::colors::RESET, color,
                    format!($($arg)*), crate::colors::RESET);
        }
    }};
}

pub(crate) use syssec_log;

pub fn local_time_hms(secs: i64) -> String {
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let t: libc::time_t = secs as libc::time_t;
    unsafe { libc::localtime_r(&t, &mut tm); }
    format!("{:02}:{:02}:{:02}", tm.tm_hour, tm.tm_min, tm.tm_sec)
}

//helpers
pub fn check_start(fmt: impl fmt::Display) {
    if (G_LOG_LEVEL.load(Ordering::SeqCst)) < LogLevel::Info as i32 { return;}
    println!("{}{} -> {}{}", BOLD, CYAN, RESET, fmt);
    use std::io::Write; let _ = std::io::stdout().flush();
}

pub fn check_item(item: &str, status: Status, extra: &str){
    if (G_LOG_LEVEL.load(Ordering::SeqCst)) < LogLevel::Info as i32 { return; }
    let (color, symbol) = match status {
        Status::Pass => (GREEN, "Y"),
        Status::Warn => (YELLOW, "W"),
        Status::Fail => (RED, "F"),
        Status::Unknown => (BLUE, "?"),
    };
    if extra.is_empty() {
        println!("   {}{}{} {:<40}", color, symbol, RESET, item);
    } else {
        println!("   {}{}{} {:<40} {}{}{}", color, symbol, RESET, item, DIM, extra, RESET);
    }
    use std::io::Write; let _ = std::io::stdout().flush();
}

#[allow(dead_code)]
pub fn check_progress(fmt: impl fmt::Display){
    if (G_LOG_LEVEL.load(Ordering::SeqCst)) < LogLevel::Info as i32 { return;}
    println!("{}    ...{}{}", DIM, fmt, RESET);
    use std::io::Write; let _ = std::io::stdout().flush();
}

//helpers
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn proc_running(name: &str) -> bool {
    std::process::Command::new("pgrep")
        .arg("-x").arg(name)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

pub fn file_exists(path: &str) -> bool {
    std::fs::metadata(path).is_ok()
}

//sysctl helpers
pub fn sysctl_string(name: &str) -> Option<String> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut buf = vec![0u8; 1024];
    let mut len: libc::size_t = buf.len();
    let r = unsafe {
        libc::sysctlbyname(cname.as_ptr(), buf.as_mut_ptr() as *mut libc::c_void,
            &mut len, std::ptr::null_mut(), 0)
    };

    if r != 0 { return None; }
    if len > 0 && buf[len as usize - 1] == 0 { len -= 1; }
    buf.truncate(len as usize);
    Some(String::from_utf8_lossy(&buf).into_owned())
}

pub fn sysctl_i32(name: &str) -> Option<i32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut val: i32 = 0;
    let mut len: libc::size_t = std::mem::size_of::<i32>();
    let r = unsafe {
        libc::sysctlbyname(cname.as_ptr(), &mut val as *mut _ as *mut libc::c_void,
            &mut len, std::ptr::null_mut(), 0)
    };
    if r == 0 { Some(val) } else { None }
}

pub fn sysctl_i64(name: &str) -> Option<i64> {
    let cname = std::ffi::CString::new(name).ok()?;
    let mut val: i64 = 0;
    let mut len: libc::size_t = std::mem::size_of::<i64>();
    let r = unsafe {
        libc::sysctlbyname(cname.as_ptr(), &mut val as *mut _ as *mut libc::c_void,
            &mut len, std::ptr::null_mut(), 0)
    };

    if r == 0 { Some(val) } else { None }
}

pub fn mode_to_string(mode: mode_t) -> String {
    let mut out = ['-'; 9];
    out[0] = if mode & libc::S_IRUSR != 0 { 'r' } else { '-' };
    out[1] = if mode & libc::S_IWUSR != 0 { 'w' } else { '-' };
    out[2] = if mode & libc::S_IXUSR != 0 { 'x' } else { '-' };
    out[3] = if mode & libc::S_IRGRP != 0 { 'r' } else { '-' };
    out[4] = if mode & libc::S_IWGRP != 0 { 'w' } else { '-' };
    out[5] = if mode & libc::S_IXGRP != 0 { 'x' } else { '-' };
    out[6] = if mode & libc::S_IROTH != 0 { 'r' } else { '-' };
    out[7] = if mode & libc::S_IWOTH != 0 { 'w' } else { '-' };
    out[8] = if mode & libc::S_IXOTH != 0 { 'x' } else { '-' };
    if mode & libc::S_ISUID != 0 { out[2] = if mode & libc::S_IXUSR != 0 { 's' } else { 'S'}; }
    if mode & libc::S_ISGID != 0 { out[5] = if mode & libc::S_IXGRP != 0 { 's'} else { 'S'}; }
    if mode & libc::S_ISVTX != 0 { out[8] = if mode & libc::S_IXOTH != 0 { 't' } else { 'T'}; }
    out.iter().collect()
}

#[allow(dead_code)]
pub type Uid = uid_t;
#[allow(dead_code)]
pub type Gid = gid_t;
#[allow(dead_code)]
pub type Off = off_t;
