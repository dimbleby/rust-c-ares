extern crate c_ares_sys;
extern crate libc;

use std::fmt;
use std::ptr;
use std::slice;

use c_types;

use error::AresError;
use hostent::{
    HasHostent,
    HostAddressResultsIter,
    HostAliasResultsIter,
    HostentOwned,
};
use utils::ares_error;

/// The result of a successful CNAME lookup.
#[derive(Debug)]
#[allow(raw_pointer_derive)]
pub struct CNameResults {
    hostent: HostentOwned,
}

impl CNameResults {
    /// Obtain a `CNameResults` from the response to a CNAME lookup.
    pub fn parse_from(data: &[u8]) -> Result<CNameResults, AresError> {
        let mut hostent: *mut c_types::hostent = ptr::null_mut();
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

    fn new(hostent: *mut c_types::hostent) -> CNameResults {
        CNameResults {
            hostent: HostentOwned::new(hostent),
        }
    }

    /// Returns the hostname from this `CNameResults`.
    pub fn hostname(&self) -> &str {
        self.hostent.hostname()
    }

    /// Returns an iterator over the `HostAddressResult` values in this
    /// `CNameResults`.
    pub fn addresses(&self) -> HostAddressResultsIter {
        self.hostent.addresses()
    }

    /// Returns an iterator over the `HostAliasResult` values in this
    /// `CNameResults`.
    pub fn aliases(&self) -> HostAliasResultsIter {
        self.hostent.aliases()
    }
}

impl fmt::Display for CNameResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.hostent.display(fmt)
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
    let handler = Box::from_raw(arg as *mut F);
    handler(result);
}
