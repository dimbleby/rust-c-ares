extern crate c_ares_sys;
extern crate libc;

use std::error;
use std::ffi::CStr;
use std::fmt::{
    Display,
    Error,
    Formatter,
};
use std::str;

/// Error codes that the library might return.
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

    /// Error loading iphlpapi.dll.
    ELOADIPHLPAPI = c_ares_sys::ARES_ELOADIPHLPAPI as isize,

    /// Could not find GetNetworkParams function.
    EADDRGETNETWORKPARAMS = c_ares_sys::ARES_EADDRGETNETWORKPARAMS as isize,

    /// DNS query cancelled.
    ECANCELLED = c_ares_sys::ARES_ECANCELLED as isize,

    /// Unknown error.
    UNKNOWN,
}

impl Display for AresError {
    fn fmt(&self, formatter: &mut Formatter) -> Result<(), Error> {
        let text = match *self {
            AresError::ENODATA => "ENODATA",
            AresError::EFORMERR => "EFORMERR",
            AresError::ESERVFAIL => "ESERVFAIL",
            AresError::ENOTFOUND => "ENOTFOUND",
            AresError::ENOTIMP => "ENOTIMP",
            AresError::EREFUSED => "EREFUSED",
            AresError::EBADQUERY => "EBADQUERY",
            AresError::EBADNAME => "EBADNAME",
            AresError::EBADFAMILY => "EBADFAMILY",
            AresError::EBADRESP => "EBADRESP",
            AresError::ECONNREFUSED => "ECONNREFUSED",
            AresError::ETIMEOUT => "ETIMEOUT",
            AresError::EOF => "EOF",
            AresError::EFILE => "EFILE",
            AresError::ENOMEM => "ENOMEM",
            AresError::EDESTRUCTION => "EDESTRUCTION",
            AresError::EBADSTR => "EBADSTR",
            AresError::EBADFLAGS => "EBADFLAGS",
            AresError::ENONAME => "ENONAME",
            AresError::EBADHINTS => "EBADHINTS",
            AresError::ENOTINITIALIZED => "ENOTINITIALIZED",
            AresError::ELOADIPHLPAPI => "ELOADIPHLPAPI",
            AresError::EADDRGETNETWORKPARAMS => "EADDRGETNETWORKPARAMS",
            AresError::ECANCELLED => "ECANCELLED",
            AresError::UNKNOWN => "UNKNOWN",
        };
        formatter.write_str(text)
    }
}

impl error::Error for AresError {
    fn description(&self) -> &str {
        unsafe {
            let ptr = c_ares_sys::ares_strerror(*self as libc::c_int);
            let buf = CStr::from_ptr(ptr).to_bytes();
            str::from_utf8_unchecked(buf)
        }
    }
}
