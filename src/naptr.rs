use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{c_int, c_uchar, c_void};
use std::ptr;
use std::slice;

use itertools::Itertools;

use crate::error::{Error, Result};
use crate::panic;
use crate::utils::{c_string_as_str_checked, hostname_as_str};

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
        if parse_status == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
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
        unsafe { c_ares_sys::ares_free_data(self.naptr_reply.cast()) }
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
    pub fn flags(self) -> &'a str {
        unsafe { c_string_as_str_checked(self.naptr_reply.flags.cast()) }
    }

    /// Returns the service name in this `NAPTRResult`.
    pub fn service_name(self) -> &'a str {
        unsafe { c_string_as_str_checked(self.naptr_reply.service.cast()) }
    }

    /// Returns the regular expression in this `NAPTRResult`.
    pub fn reg_exp(self) -> &'a str {
        unsafe { c_string_as_str_checked(self.naptr_reply.regexp.cast()) }
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

impl<'a> fmt::Display for NAPTRResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Flags: {}, ", self.flags())?;
        write!(fmt, "Service name: {}, ", self.service_name())?;
        write!(fmt, "Regular expression: {}, ", self.reg_exp())?;
        write!(fmt, "Replacement pattern: {}, ", self.replacement_pattern())?;
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
    ares_callback!(
        arg.cast::<F>(),
        status,
        abuf,
        alen,
        NAPTRResults::parse_from
    );
}
