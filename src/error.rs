use std::error;
use std::ffi::CStr;
use std::fmt;
use std::os::raw::c_int;
use std::result;
use std::str;

use c_ares_sys;

/// Error codes that the library might return.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
pub enum Error {
    /// DNS server returned answer with no data.
    ENODATA = c_ares_sys::ARES_ENODATA as isize,

    /// DNS server claims query was misformatted.
    EFORMERR = c_ares_sys::ARES_EFORMERR as isize,

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

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        let text = unsafe {
            let ptr = c_ares_sys::ares_strerror(*self as c_int);
            let buf = CStr::from_ptr(ptr).to_bytes();
            str::from_utf8_unchecked(buf)
        };
        fmt.write_str(text)
    }
}

impl From<i32> for Error {
    fn from(code: i32) -> Self {
        match code {
            c_ares_sys::ARES_ENODATA => Error::ENODATA,
            c_ares_sys::ARES_EFORMERR => Error::EFORMERR,
            c_ares_sys::ARES_ESERVFAIL => Error::ESERVFAIL,
            c_ares_sys::ARES_ENOTFOUND => Error::ENOTFOUND,
            c_ares_sys::ARES_ENOTIMP => Error::ENOTIMP,
            c_ares_sys::ARES_EREFUSED => Error::EREFUSED,
            c_ares_sys::ARES_EBADQUERY => Error::EBADQUERY,
            c_ares_sys::ARES_EBADNAME => Error::EBADNAME,
            c_ares_sys::ARES_EBADFAMILY => Error::EBADFAMILY,
            c_ares_sys::ARES_EBADRESP => Error::EBADRESP,
            c_ares_sys::ARES_ECONNREFUSED => Error::ECONNREFUSED,
            c_ares_sys::ARES_ETIMEOUT => Error::ETIMEOUT,
            c_ares_sys::ARES_EOF => Error::EOF,
            c_ares_sys::ARES_EFILE => Error::EFILE,
            c_ares_sys::ARES_ENOMEM => Error::ENOMEM,
            c_ares_sys::ARES_EDESTRUCTION => Error::EDESTRUCTION,
            c_ares_sys::ARES_EBADSTR => Error::EBADSTR,
            c_ares_sys::ARES_EBADFLAGS => Error::EBADFLAGS,
            c_ares_sys::ARES_ENONAME => Error::ENONAME,
            c_ares_sys::ARES_EBADHINTS => Error::EBADHINTS,
            c_ares_sys::ARES_ENOTINITIALIZED => Error::ENOTINITIALIZED,
            c_ares_sys::ARES_ELOADIPHLPAPI => Error::ELOADIPHLPAPI,
            c_ares_sys::ARES_EADDRGETNETWORKPARAMS => Error::EADDRGETNETWORKPARAMS,
            c_ares_sys::ARES_ECANCELLED => Error::ECANCELLED,
            _ => Error::UNKNOWN,
        }
    }
}

/// The type used by this library for methods that might fail.
pub type Result<T> = result::Result<T, Error>;
