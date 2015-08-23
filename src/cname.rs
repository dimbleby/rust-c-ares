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

/// The result of a successful CNAME lookup.  Details can be extracted via the
/// `HostEntResults` trait.
#[derive(Debug)]
#[allow(raw_pointer_derive)]
pub struct CNameResults {
    hostent: *mut hostent,
    phantom: PhantomData<hostent>,
}

impl AsRef<hostent> for CNameResults {
    fn as_ref(&self) -> &hostent {
        unsafe { &*self.hostent }
    }
}

impl CNameResults {
    /// Obtain a `CNameResults` from the response to a CNAME lookup.
    pub fn parse_from(data: &[u8]) -> Result<CNameResults, AresError> {
        let mut hostent: *mut hostent = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_a_reply(
                data.as_ptr(),
                data.len() as libc::c_int,
                &mut hostent
                    as *mut *mut _ as *mut *mut c_ares_sys::Struct_hostent,
                ptr::null_mut(),
                ptr::null_mut())
        };
        if parse_status != c_ares_sys::ARES_SUCCESS {
            Err(ares_error(parse_status))
        } else {
            let result = CNameResults::new(hostent);
            Ok(result)
        }
    }

    fn new(hostent: *mut hostent) -> CNameResults {
        CNameResults {
            hostent: hostent,
            phantom: PhantomData,
        }
    }
}

impl fmt::Display for CNameResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.as_ref().fmt(fmt)
    }
}

impl Drop for CNameResults {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_hostent(
                self.hostent as *mut c_ares_sys::Struct_hostent);
        }
    }
}

unsafe impl Send for CNameResults { }
unsafe impl Sync for CNameResults { }

pub unsafe extern "C" fn query_cname_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<CNameResults, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        CNameResults::parse_from(data)
    };
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}
