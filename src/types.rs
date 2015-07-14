extern crate c_ares_sys;
extern crate libc;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io;

pub const INVALID_FD: io::RawFd = c_ares_sys::ARES_SOCKET_BAD as io::RawFd;

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

pub struct AResult {
        pub ip_addrs: Vec<Ipv4Addr>,
}

pub struct AAAAResult {
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
