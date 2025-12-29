use std::fmt;
use std::os::raw::{c_int, c_uchar, c_void};
use std::ptr;
use std::slice;

use crate::error::{Error, Result};
use crate::panic;
use crate::utils::hostname_as_str;

/// The result of a successful SOA lookup.
#[derive(Debug)]
pub struct SOAResult {
    soa_reply: *mut c_ares_sys::ares_soa_reply,
}

impl SOAResult {
    /// Obtain an `SOAResult` from the response to an SOA lookup.
    pub fn parse_from(data: &[u8]) -> Result<SOAResult> {
        let mut soa_reply: *mut c_ares_sys::ares_soa_reply = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_soa_reply(data.as_ptr(), data.len() as c_int, &mut soa_reply)
        };
        if parse_status == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            let result = SOAResult::new(soa_reply);
            Ok(result)
        } else {
            Err(Error::from(parse_status))
        }
    }

    fn new(soa_reply: *mut c_ares_sys::ares_soa_reply) -> Self {
        SOAResult { soa_reply }
    }

    /// Returns the name server from this `SOAResult`.
    pub fn name_server(&self) -> &str {
        unsafe { hostname_as_str((*self.soa_reply).nsname) }
    }

    /// Returns the hostmaster from this `SOAResult`.
    pub fn hostmaster(&self) -> &str {
        unsafe { hostname_as_str((*self.soa_reply).hostmaster) }
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
        write!(fmt, "Name server: {}, ", self.name_server())?;
        write!(fmt, "Hostmaster: {}, ", self.hostmaster())?;
        write!(fmt, "Serial: {}, ", self.serial())?;
        write!(fmt, "Refresh: {}, ", self.refresh())?;
        write!(fmt, "Retry: {}, ", self.retry())?;
        write!(fmt, "Expire: {}, ", self.expire())?;
        write!(fmt, "Minimum time-to-live: {}", self.min_ttl())
    }
}

impl Drop for SOAResult {
    fn drop(&mut self) {
        unsafe { c_ares_sys::ares_free_data(self.soa_reply.cast()) }
    }
}

unsafe impl Send for SOAResult {}
unsafe impl Sync for SOAResult {}

pub(crate) unsafe extern "C" fn query_soa_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *const c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<SOAResult>) + Send + 'static,
{
    ares_callback!(arg.cast::<F>(), status, abuf, alen, SOAResult::parse_from);
}
