extern crate c_ares_sys;
extern crate libc;

use std::marker::PhantomData;
use std::mem;
use std::ptr;
use std::slice;

use types::{
    AresError,
};
use utils::ares_error;

/// The result of a successful lookup for an SRV record.
pub struct SRVResult {
    pub host: c_ares_sys::Struct_ares_srv_reply,
}

impl SRVResult {
    /// Obtain an SRVResult from the response to an SRV lookup.
    pub fn parse_from(data: &[u8]) -> Result<SRVResult, AresError> {
        // TODO
        Err(ares_error(0))
    }

    fn new(host: *mut c_ares_sys::Struct_ares_srv_reply) -> SRVResult {
        SRVResult {
            host: host,
        }
    }

    /// Returns an iterator over the `host: TODO` values in this `SRVResult`.
    pub fn iter(&self) -> SRVResultIterator {
        SRVResultIterator {
            next: unsafe { (*self.host).next },
            phantom: PhantomData,
        }
    }
}

pub struct SRVResultIntoIterator {
    next: *mut *mut libc::c_char,

    // Access to the SRV responses is all through the `next` pointer, but we
    // need to keep the SRVResult around so that this points to valid memory.
    #[allow(dead_code)]
    srv_result: SRVResult,
}

pub struct SRVResultIterator<'a> {
    next: *mut *mut libc::c_char,

    // We need the phantom data to make sure that the `next` pointer remains
    // valid through the lifetime of this structure.
    phantom: PhantomData<&'a SRVResult>,
}

impl IntoIterator for SRVResult {
    type Item = TODO;
    type IntoIter = SRVResultIntoIterator;

    fn into_iter(self) -> Self::IntoIter {
        SRVResultIntoIterator {
            next: unsafe { (*self.host).next },
            srv_result: self,
        }
    }
}

impl<'a> IntoIterator for &'a SRVResult {
    type Item = TODO;
    type IntoIter = SRVResultIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        SRVResultIterator {
            next: unsafe { (*self.host).next },
            phantom: PhantomData,
        }
    }
}

impl Iterator for SRVResultIntoIterator {
    type Item = TODO;
    fn next(&mut self) -> Option<TODO> {
        unsafe {
            None //TODO
        }
    }
}

impl<'a> Iterator for SRVResultIterator<'a> {
    type Item = TODO;
    fn next(&mut self) -> Option<TODO> {
        unsafe {
            None //TODO
        }
    }
}

impl Drop for SRVResult {
    fn drop(&mut self) {
        unsafe {
            // free_mem?
            // c_ares_sys::ares_free_hostent(
            //    self.hostent as *mut c_ares_sys::Struct_hostent);
        }
    }
}
pub unsafe extern "C" fn query_srv_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<SRVResult, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        parse_srv_result(data)
    };
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}
