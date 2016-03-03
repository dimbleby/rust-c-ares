extern crate c_ares_sys;

use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{
    c_char,
    c_int,
    c_uchar,
    c_void,
};
use std::str;
use std::ptr;
use std::slice;

use error::AresError;
use utils::ares_error;

/// The result of a successful NAPTR lookup.
#[derive(Debug)]
pub struct NAPTRResults {
    naptr_reply: *mut c_ares_sys::Struct_ares_naptr_reply,
    phantom: PhantomData<c_ares_sys::Struct_ares_naptr_reply>,
}

/// The contents of a single NAPTR record.
#[derive(Clone, Copy, Debug)]
pub struct NAPTRResult<'a> {
    naptr_reply: *const c_ares_sys::Struct_ares_naptr_reply,
    phantom: PhantomData<&'a c_ares_sys::Struct_ares_naptr_reply>,
}

impl NAPTRResults {
    /// Obtain a `NAPTRResults` from the response to a NAPTR lookup.
    pub fn parse_from(data: &[u8]) -> Result<NAPTRResults, AresError> {
        let mut naptr_reply: *mut c_ares_sys::Struct_ares_naptr_reply =
            ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_naptr_reply(
                data.as_ptr(),
                data.len() as c_int,
                &mut naptr_reply)
        };
        if parse_status == c_ares_sys::ARES_SUCCESS {
            let naptr_result = NAPTRResults::new(naptr_reply);
            Ok(naptr_result)
        } else {
            Err(ares_error(parse_status))
        }
    }

    fn new(
        reply: *mut c_ares_sys::Struct_ares_naptr_reply) -> NAPTRResults {
        NAPTRResults {
            naptr_reply: reply,
            phantom: PhantomData,
        }
    }

    /// Returns an iterator over the `NAPTRResult` values in this
    /// `NAPTRResults`.
    pub fn iter(&self) -> NAPTRResultsIter {
        NAPTRResultsIter {
            next: self.naptr_reply,
            phantom: PhantomData,
        }
    }
}

impl fmt::Display for NAPTRResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(fmt, "["));
        let mut first = true;
        for naptr_result in self {
            let prefix = if first { "" } else { ", " };
            first = false;
            try!(write!(fmt, "{}{{{}}}", prefix, naptr_result));
        }
        try!(write!(fmt, "]"));
        Ok(())
    }
}

/// Iterator of `NAPTRResult`s.
#[derive(Clone, Copy, Debug)]
pub struct NAPTRResultsIter<'a> {
    next: *const c_ares_sys::Struct_ares_naptr_reply,
    phantom: PhantomData<&'a c_ares_sys::Struct_ares_naptr_reply>,
}

impl<'a> Iterator for NAPTRResultsIter<'a> {
    type Item = NAPTRResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let naptr_reply = self.next;
        if naptr_reply.is_null() {
            None
        } else {
            self.next = unsafe { (*naptr_reply).next };
            let naptr_result = NAPTRResult {
                naptr_reply: naptr_reply,
                phantom: PhantomData,
            };
            Some(naptr_result)
        }
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
        unsafe {
            c_ares_sys::ares_free_data(self.naptr_reply as *mut c_void);
        }
    }
}

unsafe impl Send for NAPTRResults { }
unsafe impl Sync for NAPTRResults { }
unsafe impl<'a> Send for NAPTRResult<'a> { }
unsafe impl<'a> Sync for NAPTRResult<'a> { }
unsafe impl<'a> Send for NAPTRResultsIter<'a> { }
unsafe impl<'a> Sync for NAPTRResultsIter<'a> { }

impl<'a> NAPTRResult<'a> {
    /// Returns the flags in this `NAPTRResult`.
    pub fn flags(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr(
                (*self.naptr_reply).flags as *const c_char);
            str::from_utf8(c_str.to_bytes()).unwrap()
        }
    }

    /// Returns the service name in this `NAPTRResult`.
    pub fn service_name(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr(
                (*self.naptr_reply).service as *const c_char);
            str::from_utf8(c_str.to_bytes()).unwrap()
        }
    }

    /// Returns the regular expression in this `NAPTRResult`.
    pub fn reg_exp(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr(
                (*self.naptr_reply).regexp as *const c_char);
            str::from_utf8(c_str.to_bytes()).unwrap()
        }
    }

    /// Returns the replacement pattern in this `NAPTRResult`.
    pub fn replacement_pattern(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr((*self.naptr_reply).replacement);
            str::from_utf8(c_str.to_bytes()).unwrap()
        }
    }

    /// Returns the order value in this `NAPTRResult`.
    pub fn order(&self) -> u16 {
        unsafe { (*self.naptr_reply).order }
    }

    /// Returns the preference value in this `NAPTRResult`.
    pub fn preference(&self) -> u16 {
        unsafe { (*self.naptr_reply).preference }
    }
}

impl<'a> fmt::Display for NAPTRResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(fmt, "Flags: {}, ", self.flags()));
        try!(write!(fmt, "Service name: {}, ", self.service_name()));
        try!(write!(fmt, "Regular expression: {}, ", self.reg_exp()));
        try!(write!(
                fmt,
                "Replacement pattern: {}, ",
                self.replacement_pattern()));
        try!(write!(fmt, "Order: {}, ", self.order()));
        try!(write!(fmt, "Preference: {}", self.preference()));
        Ok(())
    }
}

pub unsafe extern "C" fn query_naptr_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int)
    where F: FnOnce(Result<NAPTRResults, AresError>) + 'static {
    let result = if status == c_ares_sys::ARES_SUCCESS {
        let data = slice::from_raw_parts(abuf, alen as usize);
        NAPTRResults::parse_from(data)
    } else {
        Err(ares_error(status))
    };
    let handler = Box::from_raw(arg as *mut F);
    handler(result);
}
