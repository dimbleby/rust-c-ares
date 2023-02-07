use std::ffi::CStr;
use std::fmt;
use std::os::raw::{c_char, c_int, c_void};

use crate::error::{Error, Result};
use crate::panic;

/// The result of a successful name-info lookup.
#[derive(Clone, Copy, Debug)]
pub struct NameInfoResult<'a> {
    node: Option<&'a c_char>,
    service: Option<&'a c_char>,
}

impl<'a> NameInfoResult<'a> {
    fn new(node: Option<&'a c_char>, service: Option<&'a c_char>) -> Self {
        NameInfoResult { node, service }
    }

    /// Returns the node from this `NameInfoResult`.
    ///
    /// In practice this is very likely to be a valid UTF-8 string, but the underlying `c-ares`
    /// library does not guarantee this - so we leave it to users to decide whether they prefer a
    /// fallible conversion, a lossy conversion, or something else altogether.
    pub fn node(&self) -> Option<&CStr> {
        self.node.map(|string| unsafe { CStr::from_ptr(string) })
    }

    /// Returns the service from this `NameInfoResult`.
    ///
    /// In practice this is very likely to be a valid UTF-8 string, but the underlying `c-ares`
    /// library does not guarantee this - so we leave it to users to decide whether they prefer a
    /// fallible conversion, a lossy conversion, or something else altogether.
    pub fn service(&self) -> Option<&CStr> {
        self.service.map(|string| unsafe { CStr::from_ptr(string) })
    }
}

impl<'a> fmt::Display for NameInfoResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let node = self
            .node()
            .map(|cstr| cstr.to_str().unwrap_or("<not utf8>"))
            .unwrap_or("<None>");
        write!(fmt, "Node: {node}, ")?;
        let service = self
            .service()
            .map(|cstr| cstr.to_str().unwrap_or("<not utf8>"))
            .unwrap_or("<None>");
        write!(fmt, "Service: {service}")
    }
}

unsafe impl<'a> Send for NameInfoResult<'a> {}
unsafe impl<'a> Sync for NameInfoResult<'a> {}

pub(crate) unsafe extern "C" fn get_name_info_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    node: *mut c_char,
    service: *mut c_char,
) where
    F: FnOnce(Result<NameInfoResult>) + Send + 'static,
{
    panic::catch(|| {
        let result = if status == c_ares_sys::ARES_SUCCESS {
            let name_info_result = NameInfoResult::new(node.as_ref(), service.as_ref());
            Ok(name_info_result)
        } else {
            Err(Error::from(status))
        };
        let handler = Box::from_raw(arg as *mut F);
        handler(result);
    });
}
