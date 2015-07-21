extern crate c_ares_sys;
extern crate libc;

use std::os::unix::io;

/// An invalid file descriptor.  Use this to represent 'no action' when calling
/// `process_fd()` on a channel.
pub const INVALID_FD: io::RawFd = c_ares_sys::ARES_SOCKET_BAD as io::RawFd;

/// Error codes that the library might return.  Use `str_error()` to convert an
/// error code into a description.
#[derive(Debug, Clone, Copy)]
pub enum AresError {
    ENODATA = c_ares_sys::ARES_ENODATA as isize,
    EFORMERR = c_ares_sys::ARES_EFORMERR  as isize,
    ESERVFAIL = c_ares_sys::ARES_ESERVFAIL as isize,
    ENOTFOUND = c_ares_sys::ARES_ENOTFOUND as isize,
    ENOTIMP = c_ares_sys::ARES_ENOTIMP as isize,
    EREFUSED = c_ares_sys::ARES_EREFUSED as isize,
    EBADQUERY = c_ares_sys::ARES_EBADQUERY as isize,
    EBADNAME = c_ares_sys::ARES_EBADNAME as isize,
    EBADFAMILY = c_ares_sys::ARES_EBADFAMILY as isize,
    EBADRESP = c_ares_sys::ARES_EBADRESP as isize,
    ECONNREFUSED = c_ares_sys::ARES_ECONNREFUSED as isize,
    ETIMEOUT = c_ares_sys::ARES_ETIMEOUT as isize,
    EOF = c_ares_sys::ARES_EOF as isize,
    EFILE = c_ares_sys::ARES_EFILE as isize,
    ENOMEM = c_ares_sys::ARES_ENOMEM as isize,
    EDESTRUCTION = c_ares_sys::ARES_EDESTRUCTION as isize,
    EBADSTR = c_ares_sys::ARES_EBADSTR as isize,
    EBADFLAGS = c_ares_sys::ARES_EBADFLAGS as isize,
    ENONAME = c_ares_sys::ARES_ENONAME as isize,
    EBADHINTS = c_ares_sys::ARES_EBADHINTS as isize,
    ENOTINITIALIZED = c_ares_sys::ARES_ENOTINITIALIZED as isize,
    ELOADIPHLPAPI = c_ares_sys::ARES_ELOADIPHLPAPI as isize,
    EADDRGETNETWORKPARAMS = c_ares_sys::ARES_EADDRGETNETWORKPARAMS as isize,
    ECANCELLED = c_ares_sys::ARES_ECANCELLED as isize,
    UNKNOWN,
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
    CNAME = 5,
    MX = 15,
    AAAA = 28,
    SRV = 33,
}

// See arpa/nameser.h
pub enum DnsClass {
   IN = 1,
}
