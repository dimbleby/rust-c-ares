use std::error;
use std::ffi::CStr;
use std::fmt;
use std::os::raw::c_int;
use std::str;

use c_ares_sys;

/// Error codes that the library might return.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
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

impl fmt::Display for AresError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> Result<(), fmt::Error> {
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
        fmt.write_str(text)
    }
}

impl error::Error for AresError {
    fn description(&self) -> &str {
        unsafe {
            let ptr = c_ares_sys::ares_strerror(*self as c_int);
            let buf = CStr::from_ptr(ptr).to_bytes();
            str::from_utf8_unchecked(buf)
        }
    }
}

impl From<c_int> for AresError {
    fn from(code: c_int) -> Self {
        match code {
            c_ares_sys::ARES_ENODATA => AresError::ENODATA,
            c_ares_sys::ARES_EFORMERR => AresError::EFORMERR,
            c_ares_sys::ARES_ESERVFAIL => AresError::ESERVFAIL,
            c_ares_sys::ARES_ENOTFOUND => AresError::ENOTFOUND,
            c_ares_sys::ARES_ENOTIMP => AresError::ENOTIMP,
            c_ares_sys::ARES_EREFUSED => AresError::EREFUSED,
            c_ares_sys::ARES_EBADQUERY => AresError::EBADQUERY,
            c_ares_sys::ARES_EBADNAME => AresError::EBADNAME,
            c_ares_sys::ARES_EBADFAMILY => AresError::EBADFAMILY,
            c_ares_sys::ARES_EBADRESP => AresError::EBADRESP,
            c_ares_sys::ARES_ECONNREFUSED => AresError::ECONNREFUSED,
            c_ares_sys::ARES_ETIMEOUT => AresError::ETIMEOUT,
            c_ares_sys::ARES_EOF => AresError::EOF,
            c_ares_sys::ARES_EFILE => AresError::EFILE,
            c_ares_sys::ARES_ENOMEM => AresError::ENOMEM,
            c_ares_sys::ARES_EDESTRUCTION => AresError::EDESTRUCTION,
            c_ares_sys::ARES_EBADSTR => AresError::EBADSTR,
            c_ares_sys::ARES_EBADFLAGS => AresError::EBADFLAGS,
            c_ares_sys::ARES_ENONAME => AresError::ENONAME,
            c_ares_sys::ARES_EBADHINTS => AresError::EBADHINTS,
            c_ares_sys::ARES_ENOTINITIALIZED => AresError::ENOTINITIALIZED,
            c_ares_sys::ARES_ELOADIPHLPAPI => AresError::ELOADIPHLPAPI,
            c_ares_sys::ARES_EADDRGETNETWORKPARAMS =>
                AresError::EADDRGETNETWORKPARAMS,
            c_ares_sys::ARES_ECANCELLED => AresError::ECANCELLED,
            _ => AresError::UNKNOWN,
        }
    }
}
