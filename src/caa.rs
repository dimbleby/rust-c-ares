use std::os::raw::{c_int, c_uchar, c_void};
use std::{fmt, ptr, slice, str};

use itertools::Itertools;

use crate::error::{Error, Result};
use crate::panic;
use crate::utils::dns_string_as_str;

/// The result of a successful CAA lookup.
#[derive(Debug)]
pub struct CAAResults {
    caa_reply: *mut c_ares_sys::ares_caa_reply,
}

/// The contents of a single CAA record.
#[derive(Clone, Copy)]
pub struct CAAResult<'a> {
    // A single result - reference into a `CAAResults`.
    caa_reply: &'a c_ares_sys::ares_caa_reply,
}

impl CAAResults {
    /// Obtain a `CAAResults` from the response to a CAA lookup.
    pub fn parse_from(data: &[u8]) -> Result<CAAResults> {
        let mut caa_reply: *mut c_ares_sys::ares_caa_reply = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_caa_reply(data.as_ptr(), data.len() as c_int, &mut caa_reply)
        };
        if parse_status == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            let caa_result = CAAResults::new(caa_reply);
            Ok(caa_result)
        } else {
            Err(Error::from(parse_status))
        }
    }

    fn new(caa_reply: *mut c_ares_sys::ares_caa_reply) -> Self {
        CAAResults { caa_reply }
    }

    /// Returns an iterator over the `CAAResult` values in this `CAAResults`.
    pub fn iter(&self) -> CAAResultsIter<'_> {
        CAAResultsIter {
            next: unsafe { self.caa_reply.as_ref() },
        }
    }
}

impl fmt::Display for CAAResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let results = self.iter().format("}, {");
        write!(fmt, "[{{{results}}}]")
    }
}

/// Iterator of `CAAResult`s.
#[derive(Clone, Copy)]
pub struct CAAResultsIter<'a> {
    next: Option<&'a c_ares_sys::ares_caa_reply>,
}

impl<'a> Iterator for CAAResultsIter<'a> {
    type Item = CAAResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let opt_reply = self.next;
        self.next = opt_reply.and_then(|reply| unsafe { reply.next.as_ref() });
        opt_reply.map(|reply| CAAResult { caa_reply: reply })
    }
}

impl<'a> IntoIterator for &'a CAAResults {
    type Item = CAAResult<'a>;
    type IntoIter = CAAResultsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Drop for CAAResults {
    fn drop(&mut self) {
        unsafe { c_ares_sys::ares_free_data(self.caa_reply.cast()) }
    }
}

unsafe impl Send for CAAResults {}
unsafe impl Sync for CAAResults {}
unsafe impl Send for CAAResult<'_> {}
unsafe impl Sync for CAAResult<'_> {}
unsafe impl Send for CAAResultsIter<'_> {}
unsafe impl Sync for CAAResultsIter<'_> {}

impl<'a> CAAResult<'a> {
    /// Is the 'critical' flag set in this `CAAResult`?
    pub fn critical(self) -> bool {
        self.caa_reply.critical != 0
    }

    /// The property represented by this `CAAResult`.
    pub fn property(self) -> &'a str {
        unsafe { dns_string_as_str(self.caa_reply.property.cast()) }
    }

    /// The value represented by this `CAAResult`.
    pub fn value(self) -> &'a [u8] {
        unsafe { slice::from_raw_parts(self.caa_reply.value, self.caa_reply.length) }
    }
}

impl fmt::Display for CAAResult<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Critical: {}, ", self.critical())?;
        write!(fmt, "Property: {}, ", self.property())?;
        let value = str::from_utf8(self.value()).unwrap_or("<binary>");
        write!(fmt, "Value: {value}")
    }
}

pub(crate) unsafe extern "C" fn query_caa_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *const c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<CAAResults>) + Send + 'static,
{
    ares_callback!(arg.cast::<F>(), status, abuf, alen, CAAResults::parse_from);
}
