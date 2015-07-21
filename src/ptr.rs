extern crate c_ares_sys;
extern crate libc;

use std::ffi::{CStr, CString};
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

/// The result of a successful PTR lookup.
pub struct PTRResults {
    // This pointer is owned by the `PTRResults`.
    hostent: *mut hostent,
}

/// The contents of a single PTR record.
pub struct PTRResult<'a> {
    // This pointer is a reference to a value in an `PTRResults`.
    h_alias: *mut libc::c_char,
    phantom: PhantomData<&'a PTRResults>,
}

impl PTRResults {
    /// Obtain an `PTRResults` from the respoptre to an PTR lookup.
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
                libc::consts::os::bsd44::AF_INET,
                &mut hostent as *mut *mut _ as *mut *mut c_ares_sys::Struct_hostent)
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
        }
    }

    /// Returns an iterator over the `PTRResult` values in this
    /// `PTRResults`.
    pub fn iter(&self) -> PTRResultsIterator {
        PTRResultsIterator {
            next: unsafe { (*self.hostent).h_aliases },
            phantom: PhantomData,
        }
    }
}

pub struct PTRResultsIterator<'a> {
    next: *mut *mut libc::c_char,
    phantom: PhantomData<&'a PTRResults>,
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
        PTRResultsIterator {
            next: unsafe { (*self.hostent).h_aliases },
            phantom: PhantomData,
        }
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

impl<'a> PTRResult<'a> {
    /// Returns the canonical name in this `PTRResult`.
    pub fn cname(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr(self.h_alias);
            str::from_utf8_unchecked(c_str.to_bytes())
        }
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
