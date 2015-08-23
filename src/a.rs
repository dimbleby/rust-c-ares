extern crate c_ares_sys;
extern crate libc;

use std::fmt;
use std::marker::PhantomData;
use std::mem;
use std::ptr;
use std::slice;

use error::AresError;
use hostent::{
    hostent,
    HostAddressResultsIterator,
    HostAliasResultsIterator,
};
use utils::ares_error;

/// The result of a successful A lookup.
#[derive(Debug)]
#[allow(raw_pointer_derive)]
pub struct AResults {
    hostent: *mut hostent,
    phantom: PhantomData<hostent>,
}

impl AResults {
    /// Obtain an `AResults` from the response to an A lookup.
    pub fn parse_from(data: &[u8]) -> Result<AResults, AresError> {
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
            let result = AResults::new(hostent);
            Ok(result)
        }
    }

    fn new(hostent: *mut hostent) -> AResults {
        AResults {
            hostent: hostent,
            phantom: PhantomData,
        }
    }

    /// Returns the hostname from this `AResults`.
    pub fn hostname(&self) -> &str {
        let hostent = unsafe { &*self.hostent };
        hostent.hostname()
    }

    /// Returns an iterator over the `HostAddressResult` values in this
    /// `AResults`.
    pub fn addresses(&self) -> HostAddressResultsIterator {
        let hostent = unsafe { &*self.hostent };
        hostent.addresses()
    }

    /// Returns an iterator over the `HostAliasResult` values in this
    /// `AResults`.
    pub fn aliases(&self) -> HostAliasResultsIterator {
        let hostent = unsafe { &*self.hostent };
        hostent.aliases()
    }
}

impl fmt::Display for AResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let hostent = unsafe { &*self.hostent };
        hostent.fmt(fmt)
    }
}

impl Drop for AResults {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_hostent(
                self.hostent as *mut c_ares_sys::Struct_hostent);
        }
    }
}

unsafe impl Send for AResults { }
unsafe impl Sync for AResults { }

pub unsafe extern "C" fn query_a_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<AResults, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        AResults::parse_from(data)
    };
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}
