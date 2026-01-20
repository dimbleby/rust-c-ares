use std::os::raw::{c_char, c_int, c_void};
use std::{fmt, str};

use crate::error::{Error, Result};
use crate::panic;
use crate::utils::{c_string_as_str_unchecked, hostname_as_str};

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
    pub fn node(&self) -> Option<&str> {
        self.node.map(|string| unsafe { hostname_as_str(string) })
    }

    /// Returns the service from this `NameInfoResult`.
    pub fn service(&self) -> Option<&str> {
        self.service
            .map(|string| unsafe { c_string_as_str_unchecked(string) })
    }
}

impl fmt::Display for NameInfoResult<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let node = self.node().unwrap_or("<None>");
        write!(fmt, "Node: {node}, ")?;
        let service = self.service().unwrap_or("<None>");
        write!(fmt, "Service: {service}")
    }
}

unsafe impl Send for NameInfoResult<'_> {}
unsafe impl Sync for NameInfoResult<'_> {}

pub(crate) unsafe extern "C" fn get_name_info_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    node: *const c_char,
    service: *const c_char,
) where
    F: FnOnce(Result<NameInfoResult>) + Send + 'static,
{
    let result = if status == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
        let name_info_result =
            NameInfoResult::new(unsafe { node.as_ref() }, unsafe { service.as_ref() });
        Ok(name_info_result)
    } else {
        Err(Error::from(status))
    };
    let handler = unsafe { Box::from_raw(arg.cast::<F>()) };
    panic::catch(|| handler(result));
}
