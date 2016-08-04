use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{
    c_int,
    c_uchar,
    c_void,
};
use std::str;
use std::ptr;
use std::slice;

use c_ares_sys;
use itertools::Itertools;

use error::AresError;

/// The result of a successful SRV lookup.
#[derive(Debug)]
pub struct SRVResults {
    srv_reply: *mut c_ares_sys::ares_srv_reply,
    phantom: PhantomData<c_ares_sys::ares_srv_reply>,
}

/// The contents of a single SRV record.
#[derive(Clone, Copy)]
pub struct SRVResult<'a> {
    // A single result - reference into an `SRVResults`.
    srv_reply: &'a c_ares_sys::ares_srv_reply,
}

impl SRVResults {
    /// Obtain an `SRVResults` from the response to an SRV lookup.
    pub fn parse_from(data: &[u8]) -> Result<SRVResults, AresError> {
        let mut srv_reply: *mut c_ares_sys::ares_srv_reply =
            ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_srv_reply(
                data.as_ptr(),
                data.len() as c_int,
                &mut srv_reply)
        };
        if parse_status == c_ares_sys::ARES_SUCCESS {
            let srv_result = SRVResults::new(srv_reply);
            Ok(srv_result)
        } else {
            Err(AresError::from(parse_status))
        }
    }

    fn new(srv_reply: *mut c_ares_sys::ares_srv_reply) -> SRVResults {
        SRVResults {
            srv_reply: srv_reply,
            phantom: PhantomData,
        }
    }

    /// Returns an iterator over the `SRVResult` values in this `SRVResults`.
    pub fn iter(&self) -> SRVResultsIter {
        SRVResultsIter {
            next: unsafe { self.srv_reply.as_ref() },
        }
    }
}

impl fmt::Display for SRVResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let results = self.iter().format_default("}, {");
        try!(write!(fmt, "[{{{}}}]", results));
        Ok(())
    }
}

/// Iterator of `SRVResult`s.
#[derive(Clone, Copy)]
pub struct SRVResultsIter<'a> {
    next: Option<&'a c_ares_sys::ares_srv_reply>,
}

impl<'a> Iterator for SRVResultsIter<'a> {
    type Item = SRVResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let opt_reply = self.next;
        self.next = opt_reply.and_then(|reply| unsafe { reply.next.as_ref() });
        opt_reply.map(|reply| {
            SRVResult {
                srv_reply: reply,
            }
        })
    }
}

impl<'a> IntoIterator for &'a SRVResults {
    type Item = SRVResult<'a>;
    type IntoIter = SRVResultsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Drop for SRVResults {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_data(self.srv_reply as *mut c_void);
        }
    }
}

unsafe impl Send for SRVResults { }
unsafe impl Sync for SRVResults { }
unsafe impl<'a> Send for SRVResult<'a> { }
unsafe impl<'a> Sync for SRVResult<'a> { }
unsafe impl<'a> Send for SRVResultsIter<'a> { }
unsafe impl<'a> Sync for SRVResultsIter<'a> { }

impl<'a> SRVResult<'a> {
    /// Returns the hostname in this `SRVResult`.
    pub fn host(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr(self.srv_reply.host);
            str::from_utf8_unchecked(c_str.to_bytes())
        }
    }

    /// Returns the weight in this `SRVResult`.
    pub fn weight(&self) -> u16 {
        self.srv_reply.weight
    }

    /// Returns the priority in this `SRVResult`.
    pub fn priority(&self) -> u16 {
        self.srv_reply.priority
    }

    /// Returns the port in this `SRVResult`.
    pub fn port(&self) -> u16 {
        self.srv_reply.port
    }
}

impl<'a> fmt::Display for SRVResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(fmt, "Host: {}, ", self.host()));
        try!(write!(fmt, "Port: {}, ", self.port()));
        try!(write!(fmt, "Priority: {}, ", self.priority()));
        try!(write!(fmt, "Weight: {}", self.weight()));
        Ok(())
    }
}

pub unsafe extern "C" fn query_srv_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int)
    where F: FnOnce(Result<SRVResults, AresError>) + 'static {
    let result = if status == c_ares_sys::ARES_SUCCESS {
        let data = slice::from_raw_parts(abuf, alen as usize);
        SRVResults::parse_from(data)
    } else {
        Err(AresError::from(status))
    };
    let handler = Box::from_raw(arg as *mut F);
    handler(result);
}
