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

/// Error codes that the library might return.  Use `str_error()` to convert an
/// error code into a description.
#[derive(Debug, Clone, Copy)]
pub enum AresError {
    /// DNS server returned answer with no data.
    ENODATA = c_ares_sys::ARES_ENODATA as isize,

    /// DNS server claims query was misformatted.
    EFORMERR = c_ares_sys::ARES_EFORMERR  as isize,

    /// DNS server returned general failure.
    ESERVFAIL = c_ares_sys::ARES_ESERVFAIL as isize,

    /// Domain name not found.
    ENOTFOUND = c_ares_sys::ARES_ENOTFOUND as isize,

    /// DNS server does not implement requested operation.
    ENOTIMP = c_ares_sys::ARES_ENOTIMP as isize,

    /// DNS server refused query.
    EREFUSED = c_ares_sys::ARES_EREFUSED as isize,

    /// Misformatted DNS query.
    EBADQUERY = c_ares_sys::ARES_EBADQUERY as isize,

    /// Misformatted domain name.
    EBADNAME = c_ares_sys::ARES_EBADNAME as isize,

    /// Unsupported address family.
    EBADFAMILY = c_ares_sys::ARES_EBADFAMILY as isize,

    /// Misformatted DNS reply.
    EBADRESP = c_ares_sys::ARES_EBADRESP as isize,

    /// Could not contact DNS servers.
    ECONNREFUSED = c_ares_sys::ARES_ECONNREFUSED as isize,

    /// Timeout while contacting DNS servers.
    ETIMEOUT = c_ares_sys::ARES_ETIMEOUT as isize,

    /// End of file.
    EOF = c_ares_sys::ARES_EOF as isize,

    /// Error reading file.
    EFILE = c_ares_sys::ARES_EFILE as isize,

    /// Out of memory.
    ENOMEM = c_ares_sys::ARES_ENOMEM as isize,

    /// Channel is being destroyed.
    EDESTRUCTION = c_ares_sys::ARES_EDESTRUCTION as isize,

    /// Misformatted string.
    EBADSTR = c_ares_sys::ARES_EBADSTR as isize,

    /// Illegal flags specified.
    EBADFLAGS = c_ares_sys::ARES_EBADFLAGS as isize,

    /// Given hostname is not numeric.
    ENONAME = c_ares_sys::ARES_ENONAME as isize,

    /// Illegal hints flags specified.
    EBADHINTS = c_ares_sys::ARES_EBADHINTS as isize,

    /// c-ares library initialization not yet performed.
    ENOTINITIALIZED = c_ares_sys::ARES_ENOTINITIALIZED as isize,

    /// rror loading iphlpapi.dll.
    ELOADIPHLPAPI = c_ares_sys::ARES_ELOADIPHLPAPI as isize,

    /// ould not find GetNetworkParams function.
    EADDRGETNETWORKPARAMS = c_ares_sys::ARES_EADDRGETNETWORKPARAMS as isize,

    /// DNS query cancelled.
    ECANCELLED = c_ares_sys::ARES_ECANCELLED as isize,

    /// Unknown error.
    UNKNOWN,
}

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
