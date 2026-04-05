use core::ffi::{c_int, c_uchar, c_void};
use std::fmt;
use std::ptr;
use std::slice;

use itertools::Itertools;

use crate::error::{Error, Result};
use crate::panic;
use crate::utils::hostname_as_str;

/// The result of a successful MX lookup.
#[derive(Debug)]
pub struct MXResults {
    mx_reply: *mut c_ares_sys::ares_mx_reply,
}

/// The contents of a single MX record.
#[derive(Clone, Copy)]
pub struct MXResult<'a> {
    mx_reply: &'a c_ares_sys::ares_mx_reply,
}

impl MXResults {
    /// Obtain an `MXResults` from the response to an MX lookup.
    pub fn parse_from(data: &[u8]) -> Result<MXResults> {
        let mut mx_reply: *mut c_ares_sys::ares_mx_reply = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_mx_reply(data.as_ptr(), data.len() as c_int, &mut mx_reply)
        };
        if parse_status == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            let result = MXResults::new(mx_reply);
            Ok(result)
        } else {
            Err(Error::from(parse_status))
        }
    }

    fn new(mx_reply: *mut c_ares_sys::ares_mx_reply) -> Self {
        MXResults { mx_reply }
    }

    /// Returns an iterator over the `MXResult` values in this `MXResults`.
    pub fn iter(&self) -> MXResultsIter<'_> {
        MXResultsIter {
            next: unsafe { self.mx_reply.as_ref() },
        }
    }
}

impl fmt::Display for MXResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let results = self.iter().format("}, {");
        write!(fmt, "[{{{results}}}]")
    }
}

/// Iterator of `MXResult`s.
#[derive(Clone, Copy, Debug)]
pub struct MXResultsIter<'a> {
    next: Option<&'a c_ares_sys::ares_mx_reply>,
}

impl<'a> Iterator for MXResultsIter<'a> {
    type Item = MXResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let opt_reply = self.next;
        self.next = opt_reply.and_then(|reply| unsafe { reply.next.as_ref() });
        opt_reply.map(|reply| MXResult { mx_reply: reply })
    }
}

impl<'a> IntoIterator for &'a MXResults {
    type Item = MXResult<'a>;
    type IntoIter = MXResultsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl std::iter::FusedIterator for MXResultsIter<'_> {}

impl Drop for MXResults {
    fn drop(&mut self) {
        unsafe { c_ares_sys::ares_free_data(self.mx_reply.cast()) }
    }
}

unsafe impl Send for MXResults {}
unsafe impl Sync for MXResults {}
unsafe impl Send for MXResult<'_> {}
unsafe impl Sync for MXResult<'_> {}
unsafe impl Send for MXResultsIter<'_> {}
unsafe impl Sync for MXResultsIter<'_> {}

impl fmt::Debug for MXResult<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MXResult")
            .field("host", &self.host())
            .field("priority", &self.priority())
            .finish()
    }
}

impl<'a> MXResult<'a> {
    /// Returns the hostname in this `MXResult`.
    pub fn host(self) -> &'a str {
        unsafe { hostname_as_str(self.mx_reply.host) }
    }

    /// Returns the priority from this `MXResult`.
    pub fn priority(self) -> u16 {
        self.mx_reply.priority
    }
}

impl fmt::Display for MXResult<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Hostname: {}, ", self.host())?;
        write!(fmt, "Priority: {}", self.priority())
    }
}

pub(crate) unsafe extern "C" fn query_mx_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<MXResults>) + Send + 'static,
{
    ares_callback!(arg.cast::<F>(), status, abuf, alen, MXResults::parse_from);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_invalid_data() {
        let result = MXResults::parse_from(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<MXResult>();
        assert_send::<MXResults>();
        assert_send::<MXResultsIter>();
    }

    #[test]
    fn is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<MXResult>();
        assert_sync::<MXResults>();
        assert_sync::<MXResultsIter>();
    }

    // DNS MX response: example.com -> mail.example.com, priority 10, TTL 300
    const ONE_MX_RECORD: &[u8] = &[
        0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78,
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x0f, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x0f, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x14, 0x00, 0x0a, 0x04, 0x6d,
        0x61, 0x69, 0x6c, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
        0x00,
    ];

    #[test]
    fn debug_mx_result() {
        let results = MXResults::parse_from(ONE_MX_RECORD).unwrap();
        let result = results.iter().next().unwrap();
        let debug = format!("{:?}", result);
        assert!(debug.contains("MXResult"));
        assert!(debug.contains("mail.example.com"));
        assert!(debug.contains("10"));
    }

    #[test]
    fn debug_mx_results_iter() {
        let results = MXResults::parse_from(ONE_MX_RECORD).unwrap();
        let iter = results.iter();
        let debug = format!("{:?}", iter);
        assert!(debug.contains("MXResultsIter"));
    }
}
