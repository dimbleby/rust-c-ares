extern crate c_ares_sys;
extern crate libc;

use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::ptr;
use std::slice;
use std::str;

use error::AresError;
use utils::ares_error;

/// The result of a successful MX lookup.
#[derive(Debug)]
#[allow(raw_pointer_derive)]
pub struct MXResults {
    mx_reply: *mut c_ares_sys::Struct_ares_mx_reply,
    phantom: PhantomData<c_ares_sys::Struct_ares_mx_reply>,
}

/// The contents of a single MX record.
#[derive(Clone, Copy, Debug)]
#[allow(raw_pointer_derive)]
pub struct MXResult<'a> {
    mx_reply: *const c_ares_sys::Struct_ares_mx_reply,
    phantom: PhantomData<&'a c_ares_sys::Struct_ares_mx_reply>,
}

impl MXResults {
    /// Obtain an `MXResults` from the response to an MX lookup.
    pub fn parse_from(data: &[u8]) -> Result<MXResults, AresError> {
        let mut mx_reply: *mut c_ares_sys::Struct_ares_mx_reply =
            ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_mx_reply(
                data.as_ptr(),
                data.len() as libc::c_int,
                &mut mx_reply)
        };
        if parse_status != c_ares_sys::ARES_SUCCESS {
            Err(ares_error(parse_status))
        } else {
            let result = MXResults::new(mx_reply);
            Ok(result)
        }
    }

    fn new(mx_reply: *mut c_ares_sys::Struct_ares_mx_reply) -> MXResults {
        MXResults {
            mx_reply: mx_reply,
            phantom: PhantomData,
        }
    }

    /// Returns an iterator over the `MXResult` values in this `MXResults`.
    pub fn iter(&self) -> MXResultsIterator {
        MXResultsIterator {
            next: self.mx_reply,
            phantom: PhantomData,
        }
    }
}

impl fmt::Display for MXResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(fmt, "["));
        let mut first = true;
        for mx_result in self {
            let prefix = if first { "" } else { ", " };
            first = false;
            try!(write!(fmt, "{}{{{}}}", prefix, mx_result));
        }
        try!(write!(fmt, "]"));
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
#[allow(raw_pointer_derive)]
pub struct MXResultsIterator<'a> {
    next: *const c_ares_sys::Struct_ares_mx_reply,
    phantom: PhantomData<&'a c_ares_sys::Struct_ares_mx_reply>,
}

impl<'a> Iterator for MXResultsIterator<'a> {
    type Item = MXResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let mx_reply = self.next;
        if mx_reply.is_null() {
            None
        } else {
            unsafe {
                self.next = (*mx_reply).next;
            }
            let mx_result = MXResult {
                mx_reply: mx_reply,
                phantom: PhantomData,
            };
            Some(mx_result)
        }
    }
}
impl<'a> IntoIterator for &'a MXResults {
    type Item = MXResult<'a>;
    type IntoIter = MXResultsIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Drop for MXResults {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_data(self.mx_reply as *mut libc::c_void);
        }
    }
}

unsafe impl Send for MXResults { }
unsafe impl Sync for MXResults { }
unsafe impl<'a> Send for MXResult<'a> { }
unsafe impl<'a> Sync for MXResult<'a> { }
unsafe impl<'a> Send for MXResultsIterator<'a> { }
unsafe impl<'a> Sync for MXResultsIterator<'a> { }

impl<'a> MXResult<'a> {
    /// Returns the hostname in this `MXResult`.
    pub fn host(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr((*self.mx_reply).host);
            str::from_utf8_unchecked(c_str.to_bytes())
        }
    }

    /// Returns the priority from this `MXResult`.
    pub fn priority(&self) -> u16 {
        unsafe { (*self.mx_reply).priority }
    }
}

impl<'a> fmt::Display for MXResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(fmt, "Hostname: {}, ", self.host()));
        try!(write!(fmt, "Priority: {}", self.priority()));
        Ok(())
    }
}

pub unsafe extern "C" fn query_mx_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<MXResults, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        MXResults::parse_from(data)
    };
    let handler = Box::from_raw(arg as *mut F);
    handler(result);
}
