extern crate c_ares_sys;
extern crate libc;

use std::fmt;
use std::marker::PhantomData;
use std::ptr;
use std::slice;

use error::AresError;
use hostent::{
    hostent,
    HostAddressResultsIterator,
    HostAliasResultsIterator,
};
use utils::ares_error;

/// The result of a successful AAAA lookup.
#[derive(Debug)]
#[allow(raw_pointer_derive)]
pub struct AAAAResults {
    hostent: *mut hostent,
    phantom: PhantomData<hostent>,
}

impl AAAAResults {
    /// Obtain an `AAAAResults` from the response to an AAAA lookup.
    pub fn parse_from(data: &[u8]) -> Result<AAAAResults, AresError> {
        let mut hostent: *mut hostent = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_aaaa_reply(
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
            let result = AAAAResults::new(hostent);
            Ok(result)
        }
    }

    fn new(hostent: *mut hostent) -> AAAAResults {
        AAAAResults {
            hostent: hostent,
            phantom: PhantomData,
        }
    }

    /// Returns the hostname from this `AAAAResults`.
    pub fn hostname(&self) -> &str {
        let hostent = unsafe { &*self.hostent };
        hostent.hostname()
    }

    /// Returns an iterator over the `HostAddressResult` values in this
    /// `AAAAResults`.
    pub fn addresses(&self) -> HostAddressResultsIterator {
        let hostent = unsafe { &*self.hostent };
        hostent.addresses()
    }

    /// Returns an iterator over the `HostAliasResult` values in this
    /// `AAAAResults`.
    pub fn aliases(&self) -> HostAliasResultsIterator {
        let hostent = unsafe { &*self.hostent };
        hostent.aliases()
    }
}

impl fmt::Display for AAAAResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let hostent = unsafe { &*self.hostent };
        hostent.fmt(fmt)
    }
}

impl Drop for AAAAResults {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_hostent(
                self.hostent as *mut c_ares_sys::Struct_hostent);
        }
    }
}

unsafe impl Send for AAAAResults { }
unsafe impl Sync for AAAAResults { }

pub unsafe extern "C" fn query_aaaa_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<AAAAResults, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        AAAAResults::parse_from(data)
    };
    let handler = Box::from_raw(arg as *mut F);
    handler(result);
}
