extern crate c_ares_sys;
extern crate libc;

use std::ffi::CStr;
use std::marker::PhantomData;
use std::mem;
use std::str;

use error::AresError;
use utils::ares_error;

/// The result of a successful name-info lookup.
pub struct NameInfoResult<'a> {
    node: *const libc::c_char,
    service: *const libc::c_char,
    phantom: PhantomData<&'a libc::c_char>,
}

impl<'a> NameInfoResult<'a> {
    fn new(
        node: *const libc::c_char,
        service: *const libc::c_char) -> NameInfoResult<'a> {
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

unsafe impl<'a> Send for NameInfoResult<'a> { }
unsafe impl<'a> Sync for NameInfoResult<'a> { }

pub unsafe extern "C" fn get_name_info_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    node: *mut libc::c_char,
    service: *mut libc::c_char)
    where F: FnOnce(Result<NameInfoResult, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let name_info_result = NameInfoResult::new(node, service);
        Ok(name_info_result)
    };
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}
