use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int, c_uchar, c_void};
use std::ptr;
use std::slice;

use itertools::Itertools;

use crate::error::{Error, Result};
use crate::panic;

/// The result of a successful NAPTR lookup.
#[derive(Debug)]
pub struct NAPTRResults {
    naptr_reply: *mut c_ares_sys::ares_naptr_reply,
    phantom: PhantomData<c_ares_sys::ares_naptr_reply>,
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
        if parse_status == c_ares_sys::ARES_SUCCESS {
            let naptr_result = NAPTRResults::new(naptr_reply);
            Ok(naptr_result)
        } else {
            Err(Error::from(parse_status))
        }
    }

    fn new(reply: *mut c_ares_sys::ares_naptr_reply) -> Self {
        NAPTRResults {
            naptr_reply: reply,
            phantom: PhantomData,
        }
    }

    /// Returns an iterator over the `NAPTRResult` values in this `NAPTRResults`.
    pub fn iter(&self) -> NAPTRResultsIter {
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
#[derive(Clone, Copy)]
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

impl Drop for NAPTRResults {
    fn drop(&mut self) {
        unsafe { c_ares_sys::ares_free_data(self.naptr_reply as *mut c_void) }
    }
}

unsafe impl Send for NAPTRResults {}
unsafe impl Sync for NAPTRResults {}
unsafe impl<'a> Send for NAPTRResult<'a> {}
unsafe impl<'a> Sync for NAPTRResult<'a> {}
unsafe impl<'a> Send for NAPTRResultsIter<'a> {}
unsafe impl<'a> Sync for NAPTRResultsIter<'a> {}

impl<'a> NAPTRResult<'a> {
    /// Returns the flags in this `NAPTRResult`.
    ///
    /// In practice this is very likely to be a valid UTF-8 string, but the underlying `c-ares`
    /// library does not guarantee this - so we leave it to users to decide whether they prefer a
    /// fallible conversion, a lossy conversion, or something else altogether.
    pub fn flags(self) -> &'a CStr {
        unsafe { CStr::from_ptr(self.naptr_reply.flags as *const c_char) }
    }

    /// Returns the service name in this `NAPTRResult`.
    ///
    /// In practice this is very likely to be a valid UTF-8 string, but the underlying `c-ares`
    /// library does not guarantee this - so we leave it to users to decide whether they prefer a
    /// fallible conversion, a lossy conversion, or something else altogether.
    pub fn service_name(self) -> &'a CStr {
        unsafe { CStr::from_ptr(self.naptr_reply.service as *const c_char) }
    }

    /// Returns the regular expression in this `NAPTRResult`.
    ///
    /// In practice this is very likely to be a valid UTF-8 string, but the underlying `c-ares`
    /// library does not guarantee this - so we leave it to users to decide whether they prefer a
    /// fallible conversion, a lossy conversion, or something else altogether.
    pub fn reg_exp(self) -> &'a CStr {
        unsafe { CStr::from_ptr(self.naptr_reply.regexp as *const c_char) }
    }

    /// Returns the replacement pattern in this `NAPTRResult`.
    ///
    /// In practice this is very likely to be a valid UTF-8 string, but the underlying `c-ares`
    /// library does not guarantee this - so we leave it to users to decide whether they prefer a
    /// fallible conversion, a lossy conversion, or something else altogether.
    pub fn replacement_pattern(self) -> &'a CStr {
        unsafe { CStr::from_ptr(self.naptr_reply.replacement) }
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

impl<'a> fmt::Display for NAPTRResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "Flags: {}, ",
            self.flags().to_str().unwrap_or("<not utf8>")
        )?;
        write!(
            fmt,
            "Service name: {}, ",
            self.service_name().to_str().unwrap_or("<not utf8>")
        )?;
        write!(
            fmt,
            "Regular expression: {}, ",
            self.reg_exp().to_str().unwrap_or("<not utf8>")
        )?;
        write!(
            fmt,
            "Replacement pattern: {}, ",
            self.replacement_pattern().to_str().unwrap_or("<not utf8>")
        )?;
        write!(fmt, "Order: {}, ", self.order())?;
        write!(fmt, "Preference: {}", self.preference())
    }
}

pub(crate) unsafe extern "C" fn query_naptr_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<NAPTRResults>) + Send + 'static,
{
    ares_callback!(arg as *mut F, status, abuf, alen, NAPTRResults::parse_from);
}
