extern crate c_ares_sys;
extern crate libc;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io;

/// Flags that may be passed when initializing a channel.
#[derive(Debug, Clone, Copy)]
pub enum Flag {
    /// Always use TCP queries (the "virtual circuit") instead of UDP queries.
    /// Normally, TCP is only used if a UDP query yields a truncated result.
    USEVC = c_ares_sys::ARES_FLAG_USEVC as isize,

    /// Only query the first server in the list of servers to query.
    PRIMARY = c_ares_sys::ARES_FLAG_PRIMARY as isize,

    /// If a truncated response to a UDP query is received, do not fall back
    /// to TCP; simply continue on with the truncated response.
    IGNTC = c_ares_sys::ARES_FLAG_IGNTC as isize,

    /// Do not set the "recursion desired" bit on outgoing queries, so that
    /// the name server being contacted will not try to fetch the answer from
    /// other servers if it doesn't know the answer locally.
    NORECURSE = c_ares_sys::ARES_FLAG_NORECURSE as isize,

    /// Do not close communications sockets when the number of active queries
    /// drops to zero.
    STAYOPEN = c_ares_sys::ARES_FLAG_STAYOPEN as isize,

    /// Do not use the default search domains; only query hostnames as-is or as
    /// aliases.
    NOSEARCH = c_ares_sys::ARES_FLAG_NOSEARCH as isize,

    /// Do not honor the HOSTALIASES environment variable, which normally
    /// specifies a file of hostname translations.
    NOALIASES = c_ares_sys::ARES_FLAG_NOALIASES as isize,

    /// Do not discard responses with the SERVFAIL, NOTIMP, or REFUSED response
    /// code or responses whose questions don't match the questions in the
    /// request. Primarily useful for writing clients which might be used to
    /// test or debug name servers.
    NOCHECKRESP = c_ares_sys::ARES_FLAG_NOCHECKRESP as isize,
    EDNS = c_ares_sys::ARES_FLAG_EDNS as isize,
}

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

/// The result of a successful lookup for an A record.
#[derive(Debug, Clone)]
pub struct AResult {
    /// The IP addresses returned by the lookup.
    pub ip_addrs: Vec<Ipv4Addr>,
}

/// The result of a successful lookup for an AAAA record.
#[derive(Debug, Clone)]
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
