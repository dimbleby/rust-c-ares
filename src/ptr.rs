extern crate c_ares_sys;
extern crate libc;

use std::ffi::{CStr, CString};
use std::fmt;
use std::marker::PhantomData;
use std::mem;
use std::ptr;
use std::slice;
use std::str;

use error::AresError;
use types::hostent;
use utils::ares_error;

/// The result of a successful PTR lookup.
#[derive(Debug)]
#[allow(raw_pointer_derive)]
pub struct PTRResults {
    hostent: *mut hostent,
    phantom: PhantomData<hostent>,
}

/// The contents of a single PTR record.
#[derive(Debug)]
#[allow(raw_pointer_derive)]
pub struct PTRResult<'a> {
    h_alias: *const libc::c_char,
    phantom: PhantomData<&'a hostent>,
}

impl PTRResults {
    /// Obtain a `PTRResults` from the response to a PTR lookup.
    pub fn parse_from(data: &[u8]) -> Result<PTRResults, AresError> {
        let mut hostent: *mut hostent = ptr::null_mut();
        let dummy_ip = "0.0.0.0";
        let c_dummy_ip = CString::new(dummy_ip).unwrap();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_ptr_reply(
                data.as_ptr(),
                data.len() as libc::c_int,
                c_dummy_ip.as_ptr() as *const libc::c_void,
                dummy_ip.len() as libc::c_int,
                libc::AF_INET,
                &mut hostent
                    as *mut *mut _ as *mut *mut c_ares_sys::Struct_hostent)
        };
        if parse_status != c_ares_sys::ARES_SUCCESS {
            Err(ares_error(parse_status))
        } else {
            let result = PTRResults::new(hostent);
            Ok(result)
        }
    }
    fn new(hostent: *mut hostent) -> PTRResults {
        PTRResults {
            hostent: hostent,
            phantom: PhantomData,
        }
    }

    /// Returns an iterator over the `PTRResult` values in this
    /// `PTRResults`.
    pub fn iter(&self) -> PTRResultsIterator {
        PTRResultsIterator {
            next: unsafe { (*self.hostent).h_aliases as *const *const _ },
            phantom: PhantomData,
        }
    }
}

impl fmt::Display for PTRResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(fmt, "["));
        let mut first = true;
        for ptr_result in self {
            let prefix = if first { "" } else { ", " };
            first = false;
            try!(write!(fmt, "{}{}", prefix, ptr_result));
        }
        try!(write!(fmt, "]"));
        Ok(())
    }
}

#[derive(Debug)]
#[allow(raw_pointer_derive)]
pub struct PTRResultsIterator<'a> {
    next: *const *const libc::c_char,
    phantom: PhantomData<&'a hostent>,
}

impl<'a> Iterator for PTRResultsIterator<'a> {
    type Item = PTRResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let h_alias = unsafe { *self.next };
        if h_alias.is_null() {
            None
        } else {
            self.next = unsafe { self.next.offset(1) };
            let ptr_result = PTRResult {
                h_alias: h_alias,
                phantom: PhantomData,
            };
            Some(ptr_result)
        }
    }
}

impl<'a> IntoIterator for &'a PTRResults {
    type Item = PTRResult<'a>;
    type IntoIter = PTRResultsIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Drop for PTRResults {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_hostent(
                self.hostent as *mut c_ares_sys::Struct_hostent);
        }
    }
}

unsafe impl Send for PTRResults { }
unsafe impl Sync for PTRResults { }
unsafe impl<'a> Send for PTRResult<'a> { }
unsafe impl<'a> Sync for PTRResult<'a> { }
unsafe impl<'a> Send for PTRResultsIterator<'a> { }
unsafe impl<'a> Sync for PTRResultsIterator<'a> { }

impl<'a> PTRResult<'a> {
    /// Returns the canonical name in this `PTRResult`.
    pub fn cname(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr(self.h_alias);
            str::from_utf8_unchecked(c_str.to_bytes())
        }
    }
}

impl<'a> fmt::Display for PTRResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.cname().fmt(fmt)
    }
}

pub unsafe extern "C" fn query_ptr_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<PTRResults, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        PTRResults::parse_from(data)
    };
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}
