extern crate c_ares_sys;
extern crate libc;

use std::ffi::CStr;
use std::marker::PhantomData;
use std::mem;
use std::str;
use std::ptr;
use std::slice;

use types::AresError;
use utils::ares_error;

/// The result of a successful SRV lookup.
pub struct SRVResults {
    srv_reply: *mut c_ares_sys::Struct_ares_srv_reply,
    phantom: PhantomData<c_ares_sys::Struct_ares_srv_reply>,
}

/// The contents of a single SRV record.
pub struct SRVResult<'a> {
    // A single result - reference into an `SRVResults`.
    srv_reply: *mut c_ares_sys::Struct_ares_srv_reply,
    phantom: PhantomData<&'a c_ares_sys::Struct_ares_srv_reply>,
}

impl SRVResults {
    /// Obtain an `SRVResults` from the response to an SRV lookup.
    pub fn parse_from(data: &[u8]) -> Result<SRVResults, AresError> {
        let mut srv_reply: *mut c_ares_sys::Struct_ares_srv_reply = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_srv_reply(
                data.as_ptr(),
                data.len() as libc::c_int,
                &mut srv_reply)
        };
        if parse_status != c_ares_sys::ARES_SUCCESS {
            Err(ares_error(parse_status))
        } else {
            let srv_result = SRVResults::new(srv_reply);
            Ok(srv_result)
        }
    }

    fn new(srv_reply: *mut c_ares_sys::Struct_ares_srv_reply) -> SRVResults {
        SRVResults {
            srv_reply: srv_reply,
            phantom: PhantomData,
        }
    }

    /// Returns an iterator over the `SRVResult` values in this `SRVResults`.
    pub fn iter(&self) -> SRVResultsIterator {
        SRVResultsIterator {
            next: self.srv_reply,
            phantom: PhantomData,
        }
    }
}

pub struct SRVResultsIterator<'a> {
    next: *mut c_ares_sys::Struct_ares_srv_reply,
    phantom: PhantomData<&'a c_ares_sys::Struct_ares_srv_reply>,
}

impl<'a> Iterator for SRVResultsIterator<'a> {
    type Item = SRVResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let srv_reply = self.next;
        if srv_reply.is_null() {
            None
        } else {
            self.next = unsafe { (*srv_reply).next };
            let srv_result = SRVResult {
                srv_reply: srv_reply,
                phantom: PhantomData,
            };
            Some(srv_result)
        }
    }
}

impl<'a> IntoIterator for &'a SRVResults {
    type Item = SRVResult<'a>;
    type IntoIter = SRVResultsIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        SRVResultsIterator {
            next: self.srv_reply,
            phantom: PhantomData,
        }
    }
}

impl Drop for SRVResults {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_data(self.srv_reply as *mut libc::c_void);
        }
    }
}

unsafe impl Send for SRVResults { }
unsafe impl Sync for SRVResults { }
unsafe impl<'a> Send for SRVResult<'a> { }
unsafe impl<'a> Sync for SRVResult<'a> { }
unsafe impl<'a> Send for SRVResultsIterator<'a> { }
unsafe impl<'a> Sync for SRVResultsIterator<'a> { }

impl<'a> SRVResult<'a> {
    /// Returns the hostname in this `SRVResult`.
    pub fn host(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr((*self.srv_reply).host);
            str::from_utf8(c_str.to_bytes()).unwrap()
        }
    }

    /// Returns the weight in this `SRVResult`.
    pub fn weight(&self) -> u16 {
        unsafe { (*self.srv_reply).weight }
    }

    /// Returns the priority in this `SRVResult`.
    pub fn priority(&self) -> u16 {
        unsafe { (*self.srv_reply).priority }
    }

    /// Returns the port in this `SRVResult`.
    pub fn port(&self) -> u16 {
        unsafe { (*self.srv_reply).port }
    }
}

pub unsafe extern "C" fn query_srv_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<SRVResults, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        SRVResults::parse_from(data)
    };
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}
