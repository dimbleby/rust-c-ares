extern crate c_ares_sys;
extern crate libc;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io;

/// An invalid file descriptor.  Use this to represent 'no action' when calling
/// `Channel::process_fd()`.
pub const INVALID_FD: io::RawFd = c_ares_sys::ARES_SOCKET_BAD as io::RawFd;

/// Error codes that the library might return.  Use `str_error()` to convert an
/// error code into a description.
#[derive(Debug)]
pub enum AresError {
    ENODATA = 1,
    EFORMERR,
    ESERVFAIL,
    ENOTFOUND,
    ENOTIMP,
    EREFUSED,
    EBADQUERY,
    EBADNAME,
    EBADFAMILY,
    EBADRESP,
    ECONNREFUSED,
    ETIMEOUT,
    EOF,
    EFILE,
    ENOMEM,
    EDESTRUCTION,
    EBADSTR,
    EBADFLAGS,
    ENONAME,
    EBADHINTS,
    ENOTINITIALIZED,
    ELOADIPHLPAPI,
    EADDRGETNETWORKPARAMS,
    ECANCELLED,
    UNKNOWN,
}

/// The result of a successful lookup for an A record.
#[derive(Debug)]
pub struct AResult {
    /// The IP addresses returned by the lookup.
    pub ip_addrs: Vec<Ipv4Addr>,
}

/// The result of a successful lookup for an AAAA record.
#[derive(Debug)]
pub struct AAAAResult {
    /// The IP addresses returned by the lookup.
    pub ip_addrs: Vec<Ipv6Addr>,
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
    AAAA = 28,
}

// See arpa/nameser.h
pub enum DnsClass {
   IN = 1,
}
