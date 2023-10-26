use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{c_int, c_uchar, c_void};
use std::ptr;
use std::slice;

use itertools::Itertools;

use crate::error::{Error, Result};
use crate::panic;

/// The result of a successful CAA lookup.
#[derive(Debug)]
pub struct CAAResults {
    caa_reply: *mut c_ares_sys::ares_caa_reply,
    phantom: PhantomData<c_ares_sys::ares_caa_reply>,
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
        CAAResults {
            caa_reply,
            phantom: PhantomData,
        }
    }

    /// Returns an iterator over the `CAAResult` values in this `CAAResults`.
    pub fn iter(&self) -> CAAResultsIter {
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
unsafe impl<'a> Send for CAAResult<'a> {}
unsafe impl<'a> Sync for CAAResult<'a> {}
unsafe impl<'a> Send for CAAResultsIter<'a> {}
unsafe impl<'a> Sync for CAAResultsIter<'a> {}

impl<'a> CAAResult<'a> {
    /// Is the 'critical' flag set in this `CAAResult`?
    pub fn critical(self) -> bool {
        self.caa_reply.critical != 0
    }

    /// The property represented by this `CAAResult`.
    ///
    /// In practice this is very likely to be a valid UTF-8 string, but the underlying `c-ares`
    /// library does not guarantee this - so we leave it to users to decide whether they prefer a
    /// fallible conversion, a lossy conversion, or something else altogether.
    pub fn property(self) -> &'a CStr {
        unsafe { CStr::from_ptr(self.caa_reply.property.cast()) }
    }

    /// The value represented by this `CAAResult`.
    ///
    /// In practice this is very likely to be a valid UTF-8 string, but the underlying `c-ares`
    /// library does not guarantee this - so we leave it to users to decide whether they prefer a
    /// fallible conversion, a lossy conversion, or something else altogether.
    pub fn value(self) -> &'a CStr {
        unsafe { CStr::from_ptr(self.caa_reply.value.cast()) }
    }
}

impl<'a> fmt::Display for CAAResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Critical: {}, ", self.critical())?;
        write!(
            fmt,
            "Property: {}, ",
            self.property().to_str().unwrap_or("<not utf8>")
        )?;
        write!(
            fmt,
            "Value: {}",
            self.value().to_str().unwrap_or("<not utf8>")
        )
    }
}

pub(crate) unsafe extern "C" fn query_caa_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<CAAResults>) + Send + 'static,
{
    ares_callback!(arg.cast::<F>(), status, abuf, alen, CAAResults::parse_from);
}
