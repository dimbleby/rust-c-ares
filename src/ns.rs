extern crate c_ares_sys;
extern crate libc;

use std::ffi::CStr;
use std::marker::PhantomData;
use std::mem;
use std::ptr;
use std::slice;
use std::str;

use types::{
    AresError,
    hostent,
};
use utils::ares_error;

/// The result of a successful NS lookup.
pub struct NSResults {
    hostent: *mut hostent,
    phantom: PhantomData<hostent>,
}

/// The contents of a single NS record.
pub struct NSResult<'a> {
    h_alias: *mut libc::c_char,
    phantom: PhantomData<&'a NSResults>,
}

impl NSResults {
    /// Obtain an `NSResults` from the response to an NS lookup.
    pub fn parse_from(data: &[u8]) -> Result<NSResults, AresError> {
        let mut hostent: *mut hostent = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_ns_reply(
                data.as_ptr(),
                data.len() as libc::c_int,
                &mut hostent as *mut *mut _ as *mut *mut c_ares_sys::Struct_hostent)
        };
        if parse_status != c_ares_sys::ARES_SUCCESS {
            Err(ares_error(parse_status))
        } else {
            let result = NSResults::new(hostent);
            Ok(result)
        }
    }
    fn new(hostent: *mut hostent) -> NSResults {
        NSResults {
            hostent: hostent,
            phantom: PhantomData,
        }
    }

    /// Returns an iterator over the `NSResult` values in this
    /// `NSResults`.
    pub fn iter(&self) -> NSResultsIterator {
        NSResultsIterator {
            next: unsafe { (*self.hostent).h_aliases },
            phantom: PhantomData,
        }
    }
}

pub struct NSResultsIterator<'a> {
    next: *mut *mut libc::c_char,
    phantom: PhantomData<&'a NSResults>,
}

impl<'a> Iterator for NSResultsIterator<'a> {
    type Item = NSResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let h_alias = unsafe { *self.next };
        if h_alias.is_null() {
            None
        } else {
            self.next = unsafe { self.next.offset(1) };
            let ns_result = NSResult {
                h_alias: h_alias,
                phantom: PhantomData,
            };
            Some(ns_result)
        }
    }
}

impl<'a> IntoIterator for &'a NSResults {
    type Item = NSResult<'a>;
    type IntoIter = NSResultsIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        NSResultsIterator {
            next: unsafe { (*self.hostent).h_aliases },
            phantom: PhantomData,
        }
    }
}

impl Drop for NSResults {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_hostent(
                self.hostent as *mut c_ares_sys::Struct_hostent);
        }
    }
}

unsafe impl Send for NSResults { }
unsafe impl Sync for NSResults { }
unsafe impl<'a> Send for NSResult<'a> { }
unsafe impl<'a> Sync for NSResult<'a> { }
unsafe impl<'a> Send for NSResultsIterator<'a> { }
unsafe impl<'a> Sync for NSResultsIterator<'a> { }

impl<'a> NSResult<'a> {
    /// Returns the name server in this `NSResult`.
    pub fn name_server(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr(self.h_alias);
            str::from_utf8_unchecked(c_str.to_bytes())
        }
    }
}

pub unsafe extern "C" fn query_ns_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<NSResults, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        NSResults::parse_from(data)
    };
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}
