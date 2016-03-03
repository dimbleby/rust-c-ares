extern crate c_ares_sys;

use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{
    c_char,
    c_int,
    c_void,
};
use std::str;

use error::AresError;
use utils::ares_error;

/// The result of a successful name-info lookup.
#[derive(Clone, Copy, Debug)]
pub struct NameInfoResult<'a> {
    node: *const c_char,
    service: *const c_char,
    phantom: PhantomData<&'a c_char>,
}

impl<'a> NameInfoResult<'a> {
    fn new(
        node: *const c_char,
        service: *const c_char) -> NameInfoResult<'a> {
        NameInfoResult {
            node: node,
            service: service,
            phantom: PhantomData,
        }
    }

    /// Returns the node from this `NameInfoResult`.
    pub fn node(&self) -> Option<&str> {
        if self.node.is_null() {
            None
        } else {
            unsafe {
                let c_str = CStr::from_ptr(self.node);
                Some(str::from_utf8_unchecked(c_str.to_bytes()))
            }
        }
    }

    /// Returns the service from this `NameInfoResult`.
    pub fn service(&self) -> Option<&str> {
        if self.service.is_null() {
            None
        } else {
            unsafe {
                let c_str = CStr::from_ptr(self.service);
                Some(str::from_utf8_unchecked(c_str.to_bytes()))
            }
        }
    }
}

impl<'a> fmt::Display for NameInfoResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let node = self.node().unwrap_or("<None>");
        try!(write!(fmt, "Node: {}, ", node));
        let service = self.service().unwrap_or("<None>");
        try!(write!(fmt, "Service: {}", service));
        Ok(())
    }
}

unsafe impl<'a> Send for NameInfoResult<'a> { }
unsafe impl<'a> Sync for NameInfoResult<'a> { }

pub unsafe extern "C" fn get_name_info_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    node: *mut c_char,
    service: *mut c_char)
    where F: FnOnce(Result<NameInfoResult, AresError>) + 'static {
    let result = if status == c_ares_sys::ARES_SUCCESS {
        let name_info_result = NameInfoResult::new(node, service);
        Ok(name_info_result)
    } else {
        Err(ares_error(status))
    };
    let handler = Box::from_raw(arg as *mut F);
    handler(result);
}
