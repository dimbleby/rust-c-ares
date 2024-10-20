use std::fmt;
use std::os::raw::{c_int, c_uchar, c_void};
use std::ptr;
use std::slice;

use itertools::Itertools;

use crate::error::{Error, Result};
use crate::panic;
use crate::utils::dns_string_as_str;

/// The result of a successful URI lookup.
#[derive(Debug)]
pub struct URIResults {
    uri_reply: *mut c_ares_sys::ares_uri_reply,
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
        if parse_status == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            let uri_result = URIResults::new(uri_reply);
            Ok(uri_result)
        } else {
            Err(Error::from(parse_status))
        }
    }

    fn new(uri_reply: *mut c_ares_sys::ares_uri_reply) -> Self {
        URIResults { uri_reply }
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
        write!(fmt, "[{{{results}}}]")
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
        unsafe { c_ares_sys::ares_free_data(self.uri_reply.cast()) }
    }
}

unsafe impl Send for URIResults {}
unsafe impl Sync for URIResults {}
unsafe impl Send for URIResult<'_> {}
unsafe impl Sync for URIResult<'_> {}
unsafe impl Send for URIResultsIter<'_> {}
unsafe impl Sync for URIResultsIter<'_> {}

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
    pub fn uri(self) -> &'a str {
        unsafe { dns_string_as_str(self.uri_reply.uri) }
    }

    /// Returns the time-to-live in this `URIResult`.
    pub fn ttl(self) -> i32 {
        #[allow(clippy::unnecessary_cast)]
        let ttl = self.uri_reply.ttl as i32;
        ttl
    }
}

impl fmt::Display for URIResult<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "URI: {}, ", self.uri())?;
        write!(fmt, "Priority: {}, ", self.priority())?;
        write!(fmt, "Weight: {}, ", self.weight())?;
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
    ares_callback!(arg.cast::<F>(), status, abuf, alen, URIResults::parse_from);
}
