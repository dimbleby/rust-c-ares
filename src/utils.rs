extern crate c_ares_sys;
extern crate libc;

use types::AresError;
use std::ffi::CStr;
use std::str;

// Convert an error code from the library into a more strongly typed AresError.
pub fn ares_error(code: libc::c_int) -> AresError {
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
        c_ares_sys::ARES_EADDRGETNETWORKPARAMS => AresError::EADDRGETNETWORKPARAMS,
        c_ares_sys::ARES_ECANCELLED => AresError::ECANCELLED,
        _ => AresError::UNKNOWN,
    }
}

/// Returns the description of an AresError. 
pub fn str_error<'a>(code: AresError) -> &'a str {
    unsafe {
        let ptr = c_ares_sys::ares_strerror(code as libc::c_int);
        let buf = CStr::from_ptr(ptr).to_bytes();
        str::from_utf8_unchecked(buf)
    }
}
