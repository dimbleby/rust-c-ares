use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int, c_uchar, c_void};
use std::ptr;
use std::slice;

use itertools::Itertools;

use crate::error::{Error, Result};
use crate::panic;

/// The result of a successful URI lookup.
#[derive(Debug)]
pub struct URIResults {
    uri_reply: *mut c_ares_sys::ares_uri_reply,
    phantom: PhantomData<c_ares_sys::ares_uri_reply>,
}

/// The contents of a single URI record.
#[derive(Clone, Copy)]
pub struct URIResult<'a> {
    // A single result - reference into a `URIResults`.
    uri_reply: &'a c_ares_sys::ares_uri_reply,
}

impl URIResults {
    /// Obtain a `URIResults` from the response to a URI lookup.
    pub fn parse_from(data: &[u8]) -> Result<URIResults> {
        let mut uri_reply: *mut c_ares_sys::ares_uri_reply = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_uri_reply(data.as_ptr(), data.len() as c_int, &mut uri_reply)
        };
        if parse_status == c_ares_sys::ARES_SUCCESS {
            let uri_result = URIResults::new(uri_reply);
            Ok(uri_result)
        } else {
            Err(Error::from(parse_status))
        }
    }

    fn new(uri_reply: *mut c_ares_sys::ares_uri_reply) -> Self {
        URIResults {
            uri_reply,
            phantom: PhantomData,
        }
    }

    /// Returns an iterator over the `URIResult` values in this `URIResults`.
    pub fn iter(&self) -> URIResultsIter {
        URIResultsIter {
            next: unsafe { self.uri_reply.as_ref() },
        }
    }
}

impl fmt::Display for URIResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let results = self.iter().format("}, {");
        write!(fmt, "[{{{}}}]", results)
    }
}

/// Iterator of `URIResult`s.
#[derive(Clone, Copy)]
pub struct URIResultsIter<'a> {
    next: Option<&'a c_ares_sys::ares_uri_reply>,
}

impl<'a> Iterator for URIResultsIter<'a> {
    type Item = URIResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let opt_reply = self.next;
        self.next = opt_reply.and_then(|reply| unsafe { reply.next.as_ref() });
        opt_reply.map(|reply| URIResult { uri_reply: reply })
    }
}

impl<'a> IntoIterator for &'a URIResults {
    type Item = URIResult<'a>;
    type IntoIter = URIResultsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Drop for URIResults {
    fn drop(&mut self) {
        unsafe { c_ares_sys::ares_free_data(self.uri_reply as *mut c_void) }
    }
}

unsafe impl Send for URIResults {}
unsafe impl Sync for URIResults {}
unsafe impl<'a> Send for URIResult<'a> {}
unsafe impl<'a> Sync for URIResult<'a> {}
unsafe impl<'a> Send for URIResultsIter<'a> {}
unsafe impl<'a> Sync for URIResultsIter<'a> {}

impl<'a> URIResult<'a> {
    /// Returns the weight in this `URIResult`.
    pub fn weight(self) -> u16 {
        self.uri_reply.weight
    }

    /// Returns the priority in this `URIResult`.
    pub fn priority(self) -> u16 {
        self.uri_reply.priority
    }

    /// Returns the uri in this `URIResult`.
    ///
    /// In practice this is very likely to be a valid UTF-8 string, but the underlying `c-ares`
    /// library does not guarantee this - so we leave it to users to decide whether they prefer a
    /// fallible conversion, a lossy conversion, or something else altogether.
    pub fn uri(self) -> &'a CStr {
        unsafe { CStr::from_ptr(self.uri_reply.uri as *const c_char) }
    }

    /// Returns the time-to-live in this `URIResult`.
    pub fn ttl(self) -> i32 {
        #[allow(clippy::unnecessary_cast)]
        let ttl = self.uri_reply.ttl as i32;
        ttl
    }
}

impl<'a> fmt::Display for URIResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "URI: {}, ",
            self.uri().to_str().unwrap_or("<not utf8>")
        )?;
        write!(fmt, "Priority: {}, ", self.priority())?;
        write!(fmt, "Weight: {}", self.weight())?;
        write!(fmt, "TTL: {}", self.ttl())
    }
}

pub(crate) unsafe extern "C" fn query_uri_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<URIResults>) + Send + 'static,
{
    ares_callback!(arg as *mut F, status, abuf, alen, URIResults::parse_from);
}
