#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

use std::ffi::c_void;
use std::mem::size_of;
use std::os::raw::{c_char, c_int};

///FreeBSD MAXPATHLEN
/// Defined by <sys/syslimits.h>
pub const MAXPATHLEN: usize = 1024;

///FreeBSD caddr_t
pub type caddr_t = *mut c_char;

/// equivalent to FreeBSD off_t
pub type off_t = i64;


/// FreeBSD `struct kld_file_stat`.
///
/// From <sys/linker.h>:
///
/// struct kld_file_stat {
///     int      version;
///     char     name[MAXPATHLEN];
///     int      refs;
///     int      id;
///     caddr_t  address;
///     size_t   size;
///     char     pathname[MAXPATHLEN];
/// };

#[repr(C)]
#[derive(Debug,Copy, Clone)]
pub struct kld_file_stat {
    pub version: c_int,
    pub name: [c_char; MAXPATHLEN],
    pub refs: c_int,
    pub id: c_int,
    pub address: caddr_t,
    pub size: usize,
    pub pathname: [c_char; MAXPATHLEN],
}

/// The value which must be placed in `kld_file_stat.version`.
///
/// FreeBSD explicitly requires this to be sizeof(struct kld_file_stat).
pub const KLD_FILE_STAT_SIZE: usize = size_of::<kld_file_stat>();

unsafe extern "C" {
    /// find a loaded KLD by name
    pub fn kldfind(file: *const c_char) -> c_int;

    /// return the ID of the next loaded KLD
    ///
    /// Passing 0 returns the first loaded KLD
    pub fn kldnext(fileid: c_int) -> c_int;

    /// get information about a loaded KLD
    pub fn kldstat(
        fileid: c_int,
        stat: *mut kld_file_stat,
    ) -> c_int;

    /// load a KLD
    pub fn kldload(file: *const c_char) -> c_int;

    /// unload a KLD
    pub fn kldunload(fileid: c_int) -> c_int;

    /// return the first module ID belonging to a KLD
    pub fn kldfirstmod(fileid: c_int) -> c_int;

    /// look up a symbol in a KLD
    pub fn kldsym(
        fileid: c_int,
        command: c_int,
        data: *mut c_void,
    ) -> c_int;
}

///FreeBSD ioctl encoding helpers
/// these correspond to <sys/ioccom.h>
const IOCPARM_MASK: u32 = 0x1fff;
const IOC_VOID: u32 = 0x20000000;
const IOC_OUT: u32 = 0x40000000;
const IOC_IN: u32 = 0x80000000;
const IOC_INOUT: u32 = IOC_IN | IOC_OUT;

/// Construct a FreeBSD `_IOR` ioctl value.
///
/// `_IOR('d', 129, off_t)` is DIOCGMEDIASIZE.
const fn ior(group: u8, number: u8, size: usize) -> u32 {
    IOC_OUT
        | (((size as u32) & IOCPARM_MASK) << 16)
        | ((group as u32) << 8)
        | number as u32
}

/// Construct a FreeBSD `_IO` ioctl value
const fn io(group: u8, number: u8) -> u32 {
    IOC_VOID | ((group as u32) << 8) | number as u32
}

/// Construct a FreeBSD `_IOW` ioctl value
const fn iow(group: u8, number: u8, size: usize) -> u32 {
    IOC_IN
       | (((size as u32) & IOCPARM_MASK) << 16)
       | ((group as u32) << 8)
       | number as u32
}

/// Construct a FreeBSD `_IOWR` ioctl value
const fn iowr(group: u8, number: u8, size: usize) -> u32 {
    IOC_INOUT
       | (((size as u32) & IOCPARM_MASK) << 16)
       | ((group as u32) << 8)
       | number as u32
}

/// Get the media size of a disk
/// #define DIOCGMEDIASIZE _IOR('d', 129, off_t)
pub const DIOCGMEDIASIZE: u32 = ior(b'd', 129, size_of::<off_t>());

/// Get the sector size of a disk
/// #define DIOCGSECTORSIZE _IOR('d', 128, u_int)
pub const DIOCGSECTORSIZE: u32 = ior(b'd', 128, size_of::<u32>());


/// FreeBSD <vm/vm_param.h> #define VM_LOADAVG 2
pub const VM_LOADAVG: c_int = 2;

/// Structure returned by FreeBSD's VM_LOADAVG sysctl
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct loadavg {
    pub ldavg: [u32; 3],
    pub fscale: c_long,
}

/// FreeBSD long is 64-bit on amd64
#[cfg(target_arch="x86_64")]
pub type c_long = i64;

/// FreeBSD `loadavg()` libc function
unsafe extern "C" {
    pub fn loadavg(
        loadavg: *mut f64,
        nelem: c_int,
    ) -> c_int;
}
