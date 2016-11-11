use std::ffi::CStr;
use std::fmt;
use std::os::raw::{
    c_char,
    c_int,
    c_void,
};
use std::str;

use c_ares_sys;

use error::Error;

/// The result of a successful name-info lookup.
#[derive(Clone, Copy, Debug)]
pub struct NameInfoResult<'a> {
    node: Option<&'a c_char>,
    service: Option<&'a c_char>,
}

impl<'a> NameInfoResult<'a> {
    fn new(
        node: Option<&'a c_char>,
        service: Option<&'a c_char>) -> NameInfoResult<'a> {
        NameInfoResult {
            node: node,
            service: service,
        }
    }

    /// Returns the node from this `NameInfoResult`.
    pub fn node(&self) -> Option<&str> {
        self.node.map(|string| {
            unsafe {
                let c_str = CStr::from_ptr(string);
                str::from_utf8_unchecked(c_str.to_bytes())
            }
        })
    }

    /// Returns the service from this `NameInfoResult`.
    pub fn service(&self) -> Option<&str> {
        self.service.map(|string| {
            unsafe {
                let c_str = CStr::from_ptr(string);
                str::from_utf8_unchecked(c_str.to_bytes())
            }
        })
    }
}

impl<'a> fmt::Display for NameInfoResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let node = self.node().unwrap_or("<None>");
        write!(fmt, "Node: {}, ", node)?;
        let service = self.service().unwrap_or("<None>");
        write!(fmt, "Service: {}", service)?;
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
    where F: FnOnce(Result<NameInfoResult, Error>) + Send + 'static {
    let result = if status == c_ares_sys::ARES_SUCCESS {
        let name_info_result = NameInfoResult::new(
            node.as_ref(),
            service.as_ref());
        Ok(name_info_result)
    } else {
        Err(Error::from(status))
    };
    let handler = Box::from_raw(arg as *mut F);
    handler(result);
}
