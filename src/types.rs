extern crate c_ares_sys;
extern crate libc;

use std::net::{
    Ipv4Addr,
    Ipv6Addr,
};
use std::os::unix::io;

/// An invalid file descriptor.  Use this to represent 'no action' when calling
/// `process_fd()` on a channel.
pub const INVALID_FD: io::RawFd = c_ares_sys::ARES_SOCKET_BAD as io::RawFd;

/// Address families.
#[derive(Debug, Clone, Copy)]
pub enum AddressFamily {
    /// IPv4.
    INET = 2,

    /// IPv6.
    INET6 = 10,
}

/// An IP address, either an IPv4 or an IPv6 address.
pub enum IpAddr {
    /// An IPv4 address.
    V4(Ipv4Addr),

    /// An IPv6 address.
    V6(Ipv6Addr),
}

#[repr(C)]
pub struct hostent {
    pub h_name: *mut libc::c_char,
    pub h_aliases: *mut *mut libc::c_char,
    pub h_addrtype: libc::c_int,
    pub h_length: libc::c_int,
    pub h_addr_list: *mut *mut libc::c_char,
}

// See arpa/nameser.h
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
pub enum DnsClass {
   IN = 1,
}
