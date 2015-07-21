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
pub struct SRVResults {
    srv_reply: *mut c_ares_sys::Struct_ares_srv_reply,
}

/// The contents of a single SRV record.
pub struct SRVResult {
    host: *mut libc::c_char,
    weight: u16,
    priority: u16,
    port: u16,
}

impl SRVResults {
    /// Obtain an SRVResult from the response to an SRV lookup.
    pub fn parse_from(data: &[u8]) -> Result<SRVResult, AresError> {
        let mut srv_reply: *mut c_ares_sys::Struct_ares_srv_reply = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_srv_reply(
                data.as_ptr(),
                data.len() as libc::c_int,
                &mut srv_reply as *mut *mut _ as *mut *mut c_ares_sys::Struct_ares_srv_reply)
        };
        if parse_status != c_ares_sys::ARES_SUCCESS {
            Err(ares_error(parse_status))
        } else {
            let result = SRVResults::new(srv_reply);
            Ok(srv_reply)
        }
    }

    fn new(srv_reply: *mut c_ares_sys::Struct_ares_srv_reply) -> SRVResults {
        SRVResults {
            srv_reply: srv_reply,
        }
    }

    /// Returns an iterator over the `SRVResult` values in this `SRVResults`.
    pub fn iter(&self) -> SRVResultsIterator {
        SRVResultsIterator {
            next: unsafe { (*self.srv_reply).next },
        }
    }
}

pub struct SRVResultsIterator {
    next: *mut c_ares_sys::Struct_ares_srv_reply,
}

impl IntoIterator for SRVResults {
    type Item = SRVResult;
    type IntoIter = SRVResultsIterator;

    fn into_iter(self) -> Self::IntoIter {
        SRVResultsIterator {
            next: unsafe { (*self.srv_reply).next },
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
        SRVResults::parse_from(data)
    };
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}
