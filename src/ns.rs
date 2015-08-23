extern crate c_ares_sys;
extern crate libc;

use std::fmt;
use std::marker::PhantomData;
use std::mem;
use std::ptr;
use std::slice;

use error::AresError;
use types::hostent;
use utils::ares_error;

/// The result of a successful NS lookup.  Details can be extracted via the
/// `HostEntResults` trait.
#[derive(Debug)]
#[allow(raw_pointer_derive)]
pub struct NSResults {
    hostent: *mut hostent,
    phantom: PhantomData<hostent>,
}

impl AsRef<hostent> for NSResults {
    fn as_ref(&self) -> &hostent {
        unsafe { &*self.hostent }
    }
}

impl NSResults {
    /// Obtain an `NSResults` from the response to an NS lookup.
    pub fn parse_from(data: &[u8]) -> Result<NSResults, AresError> {
        let mut hostent: *mut hostent = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_ns_reply(
                data.as_ptr(),
                data.len() as libc::c_int,
                &mut hostent
                    as *mut *mut _ as *mut *mut c_ares_sys::Struct_hostent)
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
}

impl fmt::Display for NSResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.as_ref().fmt(fmt)
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
