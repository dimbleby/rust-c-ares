extern crate c_ares_sys;
extern crate libc;

use std::ffi::CStr;
use std::marker::PhantomData;
use std::mem;
use std::ptr;
use std::slice;
use std::str;

use types::AresError;
use utils::ares_error;

/// The result of a successful TXT lookup.
pub struct TXTResults {
    txt_reply: *mut c_ares_sys::Struct_ares_txt_reply,
    phantom: PhantomData<c_ares_sys::Struct_ares_txt_reply>,
}

/// The contents of a single TXT record.
pub struct TXTResult<'a> {
    txt_reply: *mut c_ares_sys::Struct_ares_txt_reply,
    phantom: PhantomData<&'a TXTResults>,
}

impl TXTResults {
    /// Obtain a `TXTResults` from the response to a TXT lookup.
    pub fn parse_from(data: &[u8]) -> Result<TXTResults, AresError> {
        let mut txt_reply: *mut c_ares_sys::Struct_ares_txt_reply = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_txt_reply(
                data.as_ptr(),
                data.len() as libc::c_int,
                &mut txt_reply)
        };
        if parse_status != c_ares_sys::ARES_SUCCESS {
            Err(ares_error(parse_status))
        } else {
            let result = TXTResults::new(txt_reply);
            Ok(result)
        }
    }
    fn new(txt_reply: *mut c_ares_sys::Struct_ares_txt_reply) -> TXTResults {
        TXTResults {
            txt_reply: txt_reply,
            phantom: PhantomData,
        }
    }

    /// Returns an iterator over the `TXTResult` values in this `TXTResults`.
    pub fn iter(&self) -> TXTResultsIterator {
        TXTResultsIterator {
            next: self.txt_reply,
            phantom: PhantomData,
        }
    }
}

pub struct TXTResultsIterator<'a> {
    next: *mut c_ares_sys::Struct_ares_txt_reply,
    phantom: PhantomData<&'a TXTResults>,
}

impl<'a> Iterator for TXTResultsIterator<'a> {
    type Item = TXTResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let txt_reply = self.next;
        if txt_reply.is_null() {
            None
        } else {
            unsafe {
                self.next = (*txt_reply).next;
            }
            let txt_result = TXTResult {
                txt_reply: txt_reply,
                phantom: PhantomData,
            };
            Some(txt_result)
        }
    }
}
impl<'a> IntoIterator for &'a TXTResults {
    type Item = TXTResult<'a>;
    type IntoIter = TXTResultsIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        TXTResultsIterator {
            next: self.txt_reply,
            phantom: PhantomData,
        }
    }
}

impl Drop for TXTResults {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_data(self.txt_reply as *mut libc::c_void);
        }
    }
}

unsafe impl Send for TXTResults { }
unsafe impl Sync for TXTResults { }
unsafe impl<'a> Send for TXTResult<'a> { }
unsafe impl<'a> Sync for TXTResult<'a> { }
unsafe impl<'a> Send for TXTResultsIterator<'a> { }
unsafe impl<'a> Sync for TXTResultsIterator<'a> { }

impl<'a> TXTResult<'a> {
    /// Returns the text in this `TXTResult`.
    pub fn text(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr((*self.txt_reply).txt as *const i8);
            str::from_utf8_unchecked(c_str.to_bytes())
        }
    }
}

pub unsafe extern "C" fn query_txt_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<TXTResults, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        TXTResults::parse_from(data)
    };
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}
