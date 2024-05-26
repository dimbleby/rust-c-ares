use std::error;
use std::fmt;
use std::os::raw::c_int;
use std::result;

use crate::utils::c_string_as_str_unchecked;

/// Error codes that the library might return.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
pub enum Error {
    /// DNS server returned answer with no data.
    ENODATA = c_ares_sys::ares_status_t::ARES_ENODATA as isize,

    /// DNS server claims query was misformatted.
    EFORMERR = c_ares_sys::ares_status_t::ARES_EFORMERR as isize,

    /// DNS server returned general failure.
    ESERVFAIL = c_ares_sys::ares_status_t::ARES_ESERVFAIL as isize,

    /// Domain name not found.
    ENOTFOUND = c_ares_sys::ares_status_t::ARES_ENOTFOUND as isize,

    /// DNS server does not implement requested operation.
    ENOTIMP = c_ares_sys::ares_status_t::ARES_ENOTIMP as isize,

    /// DNS server refused query.
    EREFUSED = c_ares_sys::ares_status_t::ARES_EREFUSED as isize,

    /// Misformatted DNS query.
    EBADQUERY = c_ares_sys::ares_status_t::ARES_EBADQUERY as isize,

    /// Misformatted domain name.
    EBADNAME = c_ares_sys::ares_status_t::ARES_EBADNAME as isize,

    /// Unsupported address family.
    EBADFAMILY = c_ares_sys::ares_status_t::ARES_EBADFAMILY as isize,

    /// Misformatted DNS reply.
    EBADRESP = c_ares_sys::ares_status_t::ARES_EBADRESP as isize,

    /// Could not contact DNS servers.
    ECONNREFUSED = c_ares_sys::ares_status_t::ARES_ECONNREFUSED as isize,

    /// Timeout while contacting DNS servers.
    ETIMEOUT = c_ares_sys::ares_status_t::ARES_ETIMEOUT as isize,

    /// End of file.
    EOF = c_ares_sys::ares_status_t::ARES_EOF as isize,

    /// Error reading file.
    EFILE = c_ares_sys::ares_status_t::ARES_EFILE as isize,

    /// Out of memory.
    ENOMEM = c_ares_sys::ares_status_t::ARES_ENOMEM as isize,

    /// Channel is being destroyed.
    EDESTRUCTION = c_ares_sys::ares_status_t::ARES_EDESTRUCTION as isize,

    /// Misformatted string.
    EBADSTR = c_ares_sys::ares_status_t::ARES_EBADSTR as isize,

    /// Illegal flags specified.
    EBADFLAGS = c_ares_sys::ares_status_t::ARES_EBADFLAGS as isize,

    /// Given hostname is not numeric.
    ENONAME = c_ares_sys::ares_status_t::ARES_ENONAME as isize,

    /// Illegal hints flags specified.
    EBADHINTS = c_ares_sys::ares_status_t::ARES_EBADHINTS as isize,

    /// c-ares library initialization not yet performed.
    ENOTINITIALIZED = c_ares_sys::ares_status_t::ARES_ENOTINITIALIZED as isize,

    /// Error loading iphlpapi.dll.
    ELOADIPHLPAPI = c_ares_sys::ares_status_t::ARES_ELOADIPHLPAPI as isize,

    /// Could not find GetNetworkParams function.
    EADDRGETNETWORKPARAMS = c_ares_sys::ares_status_t::ARES_EADDRGETNETWORKPARAMS as isize,

    /// DNS query cancelled.
    ECANCELLED = c_ares_sys::ares_status_t::ARES_ECANCELLED as isize,

    /// The textual service name provided could not be dereferenced into a port.
    ESERVICE = c_ares_sys::ares_status_t::ARES_ESERVICE as isize,

    /// No DNS servers were configured.
    ENOSERVER = c_ares_sys::ares_status_t::ARES_ENOSERVER as isize,

    /// Unknown error.
    UNKNOWN,
}

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> result::Result<(), fmt::Error> {
        let text = unsafe {
            let ptr = c_ares_sys::ares_strerror(*self as c_int);
            c_string_as_str_unchecked(ptr)
        };
        fmt.write_str(text)
    }
}

impl From<i32> for Error {
    fn from(code: i32) -> Self {
        match code {
            x if x == Error::ENODATA as i32 => Error::ENODATA,
            x if x == Error::EFORMERR as i32 => Error::EFORMERR,
            x if x == Error::ESERVFAIL as i32 => Error::ESERVFAIL,
            x if x == Error::ENOTFOUND as i32 => Error::ENOTFOUND,
            x if x == Error::ENOTIMP as i32 => Error::ENOTIMP,
            x if x == Error::EREFUSED as i32 => Error::EREFUSED,
            x if x == Error::EBADQUERY as i32 => Error::EBADQUERY,
            x if x == Error::EBADNAME as i32 => Error::EBADNAME,
            x if x == Error::EBADFAMILY as i32 => Error::EBADFAMILY,
            x if x == Error::EBADRESP as i32 => Error::EBADRESP,
            x if x == Error::ECONNREFUSED as i32 => Error::ECONNREFUSED,
            x if x == Error::ETIMEOUT as i32 => Error::ETIMEOUT,
            x if x == Error::EOF as i32 => Error::EOF,
            x if x == Error::EFILE as i32 => Error::EFILE,
            x if x == Error::ENOMEM as i32 => Error::ENOMEM,
            x if x == Error::EDESTRUCTION as i32 => Error::EDESTRUCTION,
            x if x == Error::EBADSTR as i32 => Error::EBADSTR,
            x if x == Error::EBADFLAGS as i32 => Error::EBADFLAGS,
            x if x == Error::ENONAME as i32 => Error::ENONAME,
            x if x == Error::EBADHINTS as i32 => Error::EBADHINTS,
            x if x == Error::ENOTINITIALIZED as i32 => Error::ENOTINITIALIZED,
            x if x == Error::ELOADIPHLPAPI as i32 => Error::ELOADIPHLPAPI,
            x if x == Error::EADDRGETNETWORKPARAMS as i32 => Error::EADDRGETNETWORKPARAMS,
            x if x == Error::ECANCELLED as i32 => Error::ECANCELLED,
            x if x == Error::ESERVICE as i32 => Error::ESERVICE,
            x if x == Error::ENOSERVER as i32 => Error::ENOSERVER,
            _ => Error::UNKNOWN,
        }
    }
}

impl TryFrom<c_ares_sys::ares_status_t> for Error {
    type Error = ();

    fn try_from(
        status: c_ares_sys::ares_status_t,
    ) -> std::result::Result<Self, <Self as TryFrom<c_ares_sys::ares_status_t>>::Error> {
        let error = match status {
            c_ares_sys::ares_status_t::ARES_SUCCESS => return Err(()),
            c_ares_sys::ares_status_t::ARES_ENODATA => Error::ENODATA,
            c_ares_sys::ares_status_t::ARES_EFORMERR => Error::EFORMERR,
            c_ares_sys::ares_status_t::ARES_ESERVFAIL => Error::ESERVFAIL,
            c_ares_sys::ares_status_t::ARES_ENOTFOUND => Error::ENOTFOUND,
            c_ares_sys::ares_status_t::ARES_ENOTIMP => Error::ENOTIMP,
            c_ares_sys::ares_status_t::ARES_EREFUSED => Error::EREFUSED,
            c_ares_sys::ares_status_t::ARES_EBADQUERY => Error::EBADQUERY,
            c_ares_sys::ares_status_t::ARES_EBADNAME => Error::EBADNAME,
            c_ares_sys::ares_status_t::ARES_EBADFAMILY => Error::EBADFAMILY,
            c_ares_sys::ares_status_t::ARES_EBADRESP => Error::EBADRESP,
            c_ares_sys::ares_status_t::ARES_ECONNREFUSED => Error::ECONNREFUSED,
            c_ares_sys::ares_status_t::ARES_ETIMEOUT => Error::ETIMEOUT,
            c_ares_sys::ares_status_t::ARES_EOF => Error::EOF,
            c_ares_sys::ares_status_t::ARES_EFILE => Error::EFILE,
            c_ares_sys::ares_status_t::ARES_ENOMEM => Error::ENOMEM,
            c_ares_sys::ares_status_t::ARES_EDESTRUCTION => Error::EDESTRUCTION,
            c_ares_sys::ares_status_t::ARES_EBADSTR => Error::EBADSTR,
            c_ares_sys::ares_status_t::ARES_EBADFLAGS => Error::EBADFLAGS,
            c_ares_sys::ares_status_t::ARES_ENONAME => Error::ENONAME,
            c_ares_sys::ares_status_t::ARES_EBADHINTS => Error::EBADHINTS,
            c_ares_sys::ares_status_t::ARES_ENOTINITIALIZED => Error::ENOTINITIALIZED,
            c_ares_sys::ares_status_t::ARES_ELOADIPHLPAPI => Error::ELOADIPHLPAPI,
            c_ares_sys::ares_status_t::ARES_EADDRGETNETWORKPARAMS => Error::EADDRGETNETWORKPARAMS,
            c_ares_sys::ares_status_t::ARES_ECANCELLED => Error::ECANCELLED,
            c_ares_sys::ares_status_t::ARES_ESERVICE => Error::ESERVICE,
            c_ares_sys::ares_status_t::ARES_ENOSERVER => Error::ENOSERVER,
        };
        Ok(error)
    }
}

/// The type used by this library for methods that might fail.
pub type Result<T> = result::Result<T, Error>;
