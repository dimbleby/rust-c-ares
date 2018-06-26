use std::ffi::CStr;
use std::fmt;
use std::os::raw::{c_int, c_uchar, c_void};
use std::ptr;
use std::slice;

use c_ares_sys;
use c_types;

use error::{Error, Result};
use hostent::{HasHostent, HostAddressResultsIter, HostAliasResultsIter, HostentOwned};
use panic;

/// The result of a successful CNAME lookup.
#[derive(Debug)]
pub struct CNameResults {
    hostent: HostentOwned,
}

impl CNameResults {
    /// Obtain a `CNameResults` from the response to a CNAME lookup.
    pub fn parse_from(data: &[u8]) -> Result<CNameResults> {
        let mut hostent: *mut c_types::hostent = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_a_reply(
                data.as_ptr(),
                data.len() as c_int,
                &mut hostent,
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        if parse_status == c_ares_sys::ARES_SUCCESS {
            let result = CNameResults::new(hostent);
            Ok(result)
        } else {
            Err(Error::from(parse_status))
        }
    }

    fn new(hostent: *mut c_types::hostent) -> CNameResults {
        CNameResults {
            hostent: HostentOwned::new(hostent),
        }
    }

    /// Returns the hostname from this `CNameResults`.
    ///
    /// In practice this is very likely to be a valid UTF-8 string, but the underlying `c-ares`
    /// library does not guarantee this - so we leave it to users to decide whether they prefer a
    /// fallible conversion, a lossy conversion, or something else altogether.
    pub fn hostname(&self) -> &CStr {
        self.hostent.hostname()
    }

    /// Returns an iterator over the `IpAddr` values in this `CNameResults`.
    pub fn addresses(&self) -> HostAddressResultsIter {
        self.hostent.addresses()
    }

    /// Returns an iterator over the host aliases in this `CNameResults`.
    pub fn aliases(&self) -> HostAliasResultsIter {
        self.hostent.aliases()
    }
}

impl fmt::Display for CNameResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.hostent.fmt(fmt)
    }
}

pub unsafe extern "C" fn query_cname_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<CNameResults>) + Send + 'static,
{
    ares_callback!(arg as *mut F, status, abuf, alen, CNameResults::parse_from);
}
