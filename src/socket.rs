extern crate c_ares_sys;

#[cfg(target_os = "linux")]
use std::os::unix::io::{
    AsRawFd,
    RawFd,
};

/// The platform-specific socket / file descriptor.
pub struct Socket(pub c_ares_sys::ares_socket_t);

#[cfg(target_os = "linux")]
impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.0
    }
}

/// An invalid socket / file descriptor.  Use this to represent 'no action'
/// when calling `process_fd()` on a channel.
pub const SOCKET_BAD: Socket = Socket(c_ares_sys::ARES_SOCKET_BAD);
