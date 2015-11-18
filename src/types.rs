extern crate c_ares_sys;
extern crate libc;

use std::fmt;
use std::net::{
    Ipv4Addr,
    Ipv6Addr,
};

use ctypes;

/// The platform-specific file descriptor / socket type.  That is, either a
/// `RawFd` or a `RawSocket`.
pub type Socket = c_ares_sys::ares_socket_t;

/// An invalid socket / file descriptor.  Use this to represent 'no action'
/// when calling `process_fd()` on a channel.
pub const SOCKET_BAD: Socket = c_ares_sys::ARES_SOCKET_BAD;

/// Address families.
#[derive(Clone, Copy, Debug)]
pub enum AddressFamily {
    /// IPv4.
    INET = ctypes::AF_INET as isize,

    /// IPv6.
    INET6 = ctypes::AF_INET6 as isize,
}

/// An IP address, either an IPv4 or an IPv6 address.
#[derive(Clone, Copy, Debug)]
pub enum IpAddr {
    /// An IPv4 address.
    V4(Ipv4Addr),

    /// An IPv6 address.
    V6(Ipv6Addr),
}

impl fmt::Display for IpAddr {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            IpAddr::V4(ref a) => a.fmt(fmt),
            IpAddr::V6(ref a) => a.fmt(fmt),
        }
    }
}

// See arpa/nameser.h
#[derive(Clone, Copy, Debug)]
pub enum QueryType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    NAPTR = 35,
}

// See arpa/nameser.h
#[derive(Clone, Copy, Debug)]
pub enum DnsClass {
   IN = 1,
}
