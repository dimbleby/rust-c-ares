use core::ffi::{c_int, c_uchar, c_void};
use std::fmt;
use std::ptr;
use std::slice;

use itertools::Itertools;

use crate::error::{Error, Result};
use crate::panic;
use crate::utils::{dns_string_as_str, hostname_as_str};

/// The result of a successful NAPTR lookup.
#[derive(Debug)]
pub struct NAPTRResults {
    naptr_reply: *mut c_ares_sys::ares_naptr_reply,
}

/// The contents of a single NAPTR record.
#[derive(Clone, Copy)]
pub struct NAPTRResult<'a> {
    naptr_reply: &'a c_ares_sys::ares_naptr_reply,
}

impl NAPTRResults {
    /// Obtain a `NAPTRResults` from the response to a NAPTR lookup.
    pub fn parse_from(data: &[u8]) -> Result<NAPTRResults> {
        let mut naptr_reply: *mut c_ares_sys::ares_naptr_reply = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_naptr_reply(data.as_ptr(), data.len() as c_int, &mut naptr_reply)
        };
        if parse_status == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            let naptr_result = NAPTRResults::new(naptr_reply);
            Ok(naptr_result)
        } else {
            Err(Error::from(parse_status))
        }
    }

    fn new(naptr_reply: *mut c_ares_sys::ares_naptr_reply) -> Self {
        NAPTRResults { naptr_reply }
    }

    /// Returns an iterator over the `NAPTRResult` values in this `NAPTRResults`.
    pub fn iter(&self) -> NAPTRResultsIter<'_> {
        NAPTRResultsIter {
            next: unsafe { self.naptr_reply.as_ref() },
        }
    }
}

impl fmt::Display for NAPTRResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let results = self.iter().format("}, {");
        write!(fmt, "[{{{results}}}]")
    }
}

/// Iterator of `NAPTRResult`s.
#[derive(Clone, Copy, Debug)]
pub struct NAPTRResultsIter<'a> {
    next: Option<&'a c_ares_sys::ares_naptr_reply>,
}

impl<'a> Iterator for NAPTRResultsIter<'a> {
    type Item = NAPTRResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let opt_reply = self.next;
        self.next = opt_reply.and_then(|reply| unsafe { reply.next.as_ref() });
        opt_reply.map(|reply| NAPTRResult { naptr_reply: reply })
    }
}

impl<'a> IntoIterator for &'a NAPTRResults {
    type Item = NAPTRResult<'a>;
    type IntoIter = NAPTRResultsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl std::iter::FusedIterator for NAPTRResultsIter<'_> {}

impl Drop for NAPTRResults {
    fn drop(&mut self) {
        unsafe { c_ares_sys::ares_free_data(self.naptr_reply.cast()) }
    }
}

unsafe impl Send for NAPTRResults {}
unsafe impl Sync for NAPTRResults {}
unsafe impl Send for NAPTRResult<'_> {}
unsafe impl Sync for NAPTRResult<'_> {}
unsafe impl Send for NAPTRResultsIter<'_> {}
unsafe impl Sync for NAPTRResultsIter<'_> {}

impl fmt::Debug for NAPTRResult<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NAPTRResult")
            .field("flags", &self.flags())
            .field("service_name", &self.service_name())
            .field("regexp", &self.regexp())
            .field("replacement_pattern", &self.replacement_pattern())
            .field("order", &self.order())
            .field("preference", &self.preference())
            .finish()
    }
}

impl<'a> NAPTRResult<'a> {
    /// Returns the flags in this `NAPTRResult`.
    pub fn flags(self) -> &'a str {
        unsafe { dns_string_as_str(self.naptr_reply.flags.cast()) }
    }

    /// Returns the service name in this `NAPTRResult`.
    pub fn service_name(self) -> &'a str {
        unsafe { dns_string_as_str(self.naptr_reply.service.cast()) }
    }

    /// Returns the regular expression in this `NAPTRResult`.
    pub fn regexp(self) -> &'a str {
        unsafe { dns_string_as_str(self.naptr_reply.regexp.cast()) }
    }

    /// Returns the replacement pattern in this `NAPTRResult`.
    pub fn replacement_pattern(self) -> &'a str {
        unsafe { hostname_as_str(self.naptr_reply.replacement) }
    }

    /// Returns the order value in this `NAPTRResult`.
    pub fn order(self) -> u16 {
        self.naptr_reply.order
    }

    /// Returns the preference value in this `NAPTRResult`.
    pub fn preference(self) -> u16 {
        self.naptr_reply.preference
    }
}

impl fmt::Display for NAPTRResult<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Flags: {}, ", self.flags())?;
        write!(fmt, "Service name: {}, ", self.service_name())?;
        write!(fmt, "Regular expression: {}, ", self.regexp())?;
        write!(fmt, "Replacement pattern: {}, ", self.replacement_pattern())?;
        write!(fmt, "Order: {}, ", self.order())?;
        write!(fmt, "Preference: {}", self.preference())
    }
}

pub(crate) unsafe extern "C" fn query_naptr_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *const c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<NAPTRResults>) + Send + 'static,
{
    ares_callback!(
        arg.cast::<F>(),
        status,
        abuf,
        alen,
        NAPTRResults::parse_from
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_invalid_data() {
        let result = NAPTRResults::parse_from(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<NAPTRResult>();
        assert_send::<NAPTRResults>();
        assert_send::<NAPTRResultsIter>();
    }

    #[test]
    fn is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<NAPTRResult>();
        assert_sync::<NAPTRResults>();
        assert_sync::<NAPTRResultsIter>();
    }

    // DNS NAPTR response: example.com -> flags="s", service="SIP+D2T", order=100, preference=10
    const ONE_NAPTR_RECORD: &[u8] = &[
        0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78,
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x23, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x23, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x26, 0x00, 0x64, 0x00, 0x0a,
        0x01, 0x73, 0x07, 0x53, 0x49, 0x50, 0x2b, 0x44, 0x32, 0x54, 0x00, 0x04, 0x5f, 0x73, 0x69,
        0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03,
        0x63, 0x6f, 0x6d, 0x00,
    ];

    #[test]
    fn debug_naptr_result() {
        let results = NAPTRResults::parse_from(ONE_NAPTR_RECORD).unwrap();
        let result = results.iter().next().unwrap();
        let debug = format!("{:?}", result);
        assert!(debug.contains("NAPTRResult"));
        assert!(debug.contains("SIP+D2T"));
        assert!(debug.contains("100"));
    }

    #[test]
    fn debug_naptr_results_iter() {
        let results = NAPTRResults::parse_from(ONE_NAPTR_RECORD).unwrap();
        let iter = results.iter();
        let debug = format!("{:?}", iter);
        assert!(debug.contains("NAPTRResultsIter"));
    }
}
