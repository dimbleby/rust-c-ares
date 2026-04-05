use core::ffi::{c_int, c_uchar, c_void};
use std::fmt;
use std::ptr;
use std::slice;
use std::str;

use itertools::Itertools;

use crate::error::{Error, Result};
use crate::panic;

/// The result of a successful TXT lookup.
#[derive(Debug)]
pub struct TXTResults {
    txt_reply: *mut c_ares_sys::ares_txt_ext,
}

/// The contents of a single TXT record.
#[derive(Clone, Copy)]
pub struct TXTResult<'a> {
    txt_reply: &'a c_ares_sys::ares_txt_ext,
}

impl TXTResults {
    /// Obtain a `TXTResults` from the response to a TXT lookup.
    pub fn parse_from(data: &[u8]) -> Result<TXTResults> {
        let mut txt_reply: *mut c_ares_sys::ares_txt_ext = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_txt_reply_ext(data.as_ptr(), data.len() as c_int, &mut txt_reply)
        };
        if parse_status == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            let result = TXTResults::new(txt_reply);
            Ok(result)
        } else {
            Err(Error::from(parse_status))
        }
    }

    fn new(txt_reply: *mut c_ares_sys::ares_txt_ext) -> Self {
        TXTResults { txt_reply }
    }

    /// Returns an iterator over the `TXTResult` values in this `TXTResults`.
    pub fn iter(&self) -> TXTResultsIter<'_> {
        TXTResultsIter {
            next: unsafe { self.txt_reply.as_ref() },
        }
    }
}

impl fmt::Display for TXTResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let results = self.iter().format("}, {");
        write!(fmt, "[{{{results}}}]")
    }
}

/// Iterator of `TXTResult`s.
#[derive(Clone, Copy, Debug)]
pub struct TXTResultsIter<'a> {
    next: Option<&'a c_ares_sys::ares_txt_ext>,
}

impl<'a> Iterator for TXTResultsIter<'a> {
    type Item = TXTResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let opt_reply = self.next;
        self.next = opt_reply.and_then(|reply| unsafe { reply.next.as_ref() });
        opt_reply.map(|reply| TXTResult { txt_reply: reply })
    }
}

impl<'a> IntoIterator for &'a TXTResults {
    type Item = TXTResult<'a>;
    type IntoIter = TXTResultsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl std::iter::FusedIterator for TXTResultsIter<'_> {}

impl Drop for TXTResults {
    fn drop(&mut self) {
        unsafe { c_ares_sys::ares_free_data(self.txt_reply.cast()) }
    }
}

unsafe impl Send for TXTResult<'_> {}
unsafe impl Sync for TXTResult<'_> {}
unsafe impl Send for TXTResults {}
unsafe impl Sync for TXTResults {}
unsafe impl Send for TXTResultsIter<'_> {}
unsafe impl Sync for TXTResultsIter<'_> {}

impl fmt::Debug for TXTResult<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TXTResult")
            .field("record_start", &self.record_start())
            .field("text", &self.text())
            .finish()
    }
}

impl<'a> TXTResult<'a> {
    /// Is this the start of a text record, or the continuation of a previous record?
    pub fn record_start(self) -> bool {
        self.txt_reply.record_start != 0
    }

    /// Returns the text in this `TXTResult`.
    ///
    /// Although text is usual here, any binary data is legal - which is why we return `&[u8]`.
    pub fn text(self) -> &'a [u8] {
        unsafe { slice::from_raw_parts(self.txt_reply.txt, self.txt_reply.length) }
    }
}

impl fmt::Display for TXTResult<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let text = str::from_utf8(self.text()).unwrap_or("<binary>");
        write!(fmt, "Record start: {}, Text: {}", self.record_start(), text)
    }
}

pub(crate) unsafe extern "C" fn query_txt_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<TXTResults>) + Send + 'static,
{
    ares_callback!(arg.cast::<F>(), status, abuf, alen, TXTResults::parse_from);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_invalid_data() {
        let result = TXTResults::parse_from(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<TXTResult>();
        assert_send::<TXTResults>();
        assert_send::<TXTResultsIter>();
    }

    #[test]
    fn is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<TXTResult>();
        assert_sync::<TXTResults>();
        assert_sync::<TXTResultsIter>();
    }

    // DNS TXT response: example.com -> "hello world", TTL 300
    const ONE_TXT_RECORD: &[u8] = &[
        0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78,
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x10, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x0c, 0x0b, 0x68, 0x65, 0x6c,
        0x6c, 0x6f, 0x20, 0x77, 0x6f, 0x72, 0x6c, 0x64,
    ];

    #[test]
    fn debug_txt_result() {
        let results = TXTResults::parse_from(ONE_TXT_RECORD).unwrap();
        let result = results.iter().next().unwrap();
        let debug = format!("{:?}", result);
        assert!(debug.contains("TXTResult"));
        assert!(debug.contains("record_start"));
        assert!(debug.contains("text"));
    }

    #[test]
    fn debug_txt_results_iter() {
        let results = TXTResults::parse_from(ONE_TXT_RECORD).unwrap();
        let iter = results.iter();
        let debug = format!("{:?}", iter);
        assert!(debug.contains("TXTResultsIter"));
    }
}
