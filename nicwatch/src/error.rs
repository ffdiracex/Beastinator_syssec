use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("capture: {0}")]
    Capture(String),

    #[error("sysctl {oid} failed: {errno}")]
    Sysctl { oid: String, errno: i32 },

    #[error("interface {0} not found")]
    NoSuchInterface(String),

    #[error("{}", permission_hint())]
    PermissionDenied,

    #[error("parse: {0}")]
    Parse(String),

    #[error("configuration: {0}")]
    Config(String),
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(target_os = "freebsd")]
fn permission_hint() -> &'static str {
    "permission denied — try running with doas/sudo, or grant yourself access to /dev/bpf"
}

#[cfg(target_os = "linux")]
fn permission_hint() -> &'static str {
    "permission denied — try running with sudo, or grant CAP_NET_RAW to the binary"
}

#[cfg(not(any(target_os = "freebsd", target_os = "linux")))]
fn permission_hint() -> &'static str {
    "permission denied"
}
