use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{c_int, c_uchar, c_void};
use std::ptr;
use std::slice;

use c_ares_sys;

use crate::error::{Error, Result};
use crate::panic;

/// The result of a successful SOA lookup.
#[derive(Debug)]
pub struct SOAResult {
    soa_reply: *mut c_ares_sys::ares_soa_reply,
    phantom: PhantomData<c_ares_sys::ares_soa_reply>,
}

impl SOAResult {
    /// Obtain an `SOAResult` from the response to an SOA lookup.
    pub fn parse_from(data: &[u8]) -> Result<SOAResult> {
        let mut soa_reply: *mut c_ares_sys::ares_soa_reply = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_soa_reply(data.as_ptr(), data.len() as c_int, &mut soa_reply)
        };
        if parse_status == c_ares_sys::ARES_SUCCESS {
            let result = SOAResult::new(soa_reply);
            Ok(result)
        } else {
            Err(Error::from(parse_status))
        }
    }

    fn new(soa_reply: *mut c_ares_sys::ares_soa_reply) -> Self {
        SOAResult {
            soa_reply,
            phantom: PhantomData,
        }
    }

    /// Returns the name server from this `SOAResult`.
    ///
    /// In practice this is very likely to be a valid UTF-8 string, but the underlying `c-ares`
    /// library does not guarantee this - so we leave it to users to decide whether they prefer a
    /// fallible conversion, a lossy conversion, or something else altogether.
    pub fn name_server(&self) -> &CStr {
        unsafe { CStr::from_ptr((*self.soa_reply).nsname) }
    }

    /// Returns the hostmaster from this `SOAResult`.
    ///
    /// In practice this is very likely to be a valid UTF-8 string, but the underlying `c-ares`
    /// library does not guarantee this - so we leave it to users to decide whether they prefer a
    /// fallible conversion, a lossy conversion, or something else altogether.
    pub fn hostmaster(&self) -> &CStr {
        unsafe { CStr::from_ptr((*self.soa_reply).hostmaster) }
    }

    /// Returns the serial number from this `SOAResult`.
    pub fn serial(&self) -> u32 {
        unsafe { (*self.soa_reply).serial }
    }

    /// Returns the refresh time from this `SOAResult`.
    pub fn refresh(&self) -> u32 {
        unsafe { (*self.soa_reply).refresh }
    }

    /// Returns the retry time from this `SOAResult`.
    pub fn retry(&self) -> u32 {
        unsafe { (*self.soa_reply).retry }
    }

    /// Returns the expire time from this `SOAResult`.
    pub fn expire(&self) -> u32 {
        unsafe { (*self.soa_reply).expire }
    }

    /// Returns the minimum time-to-live from this `SOAResult`.
    pub fn min_ttl(&self) -> u32 {
        unsafe { (*self.soa_reply).minttl }
    }
}

impl fmt::Display for SOAResult {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "Name server: {}, ",
            self.name_server().to_str().unwrap_or("<not utf8>")
        )?;
        write!(
            fmt,
            "Hostmaster: {}, ",
            self.hostmaster().to_str().unwrap_or("<not utf8>")
        )?;
        write!(fmt, "Serial: {}, ", self.serial())?;
        write!(fmt, "Refresh: {}, ", self.refresh())?;
        write!(fmt, "Retry: {}, ", self.retry())?;
        write!(fmt, "Expire: {}, ", self.expire())?;
        write!(fmt, "Minimum time-to-live: {}", self.min_ttl())
    }
}

impl Drop for SOAResult {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_data(self.soa_reply as *mut c_void);
        }
    }
}

unsafe impl Send for SOAResult {}
unsafe impl Sync for SOAResult {}

pub unsafe extern "C" fn query_soa_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<SOAResult>) + Send + 'static,
{
    ares_callback!(arg as *mut F, status, abuf, alen, SOAResult::parse_from);
}
