use core::ffi::{c_int, c_uchar, c_void};
use std::fmt;
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
    pub fn iter(&self) -> URIResultsIter<'_> {
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
#[derive(Clone, Copy, Debug)]
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

impl std::iter::FusedIterator for URIResultsIter<'_> {}

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

impl fmt::Debug for URIResult<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("URIResult")
            .field("uri", &self.uri())
            .field("priority", &self.priority())
            .field("weight", &self.weight())
            .field("ttl", &self.ttl())
            .finish()
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_invalid_data() {
        let result = URIResults::parse_from(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<URIResult>();
        assert_send::<URIResults>();
        assert_send::<URIResultsIter>();
    }

    // DNS URI response: example.com -> "https://example.com", priority 10, weight 1, TTL 300
    const ONE_URI_RECORD: &[u8] = &[
        0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78,
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x01, 0x00, 0x00, 0x01, 0xc0,
        0x0c, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x17, 0x00, 0x0a, 0x00, 0x01,
        0x68, 0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x2e, 0x63, 0x6f, 0x6d,
    ];

    #[test]
    fn debug_uri_result() {
        let results = URIResults::parse_from(ONE_URI_RECORD).unwrap();
        let result = results.iter().next().unwrap();
        let debug = format!("{:?}", result);
        assert!(debug.contains("URIResult"));
        assert!(debug.contains("https://example.com"));
        assert!(debug.contains("10"));
    }

    #[test]
    fn debug_uri_results_iter() {
        let results = URIResults::parse_from(ONE_URI_RECORD).unwrap();
        let iter = results.iter();
        let debug = format!("{:?}", iter);
        assert!(debug.contains("URIResultsIter"));
    }
}
