extern crate c_ares_sys;
extern crate libc;

use std::ffi::CStr;
use std::marker::PhantomData;
use std::mem;
use std::str;
use std::ptr;
use std::slice;

use error::AresError;
use utils::ares_error;

/// The result of a successful NAPTR lookup.
pub struct NAPTRResults {
    naptr_reply: *mut c_ares_sys::Struct_ares_naptr_reply,
    phantom: PhantomData<c_ares_sys::Struct_ares_naptr_reply>,
}

/// The contents of a single NAPTR record.
pub struct NAPTRResult<'a> {
    naptr_reply: *const c_ares_sys::Struct_ares_naptr_reply,
    phantom: PhantomData<&'a c_ares_sys::Struct_ares_naptr_reply>,
}

impl NAPTRResults {
    #[cfg(feature = "old-cares")]
    pub fn parse_from(_data: &[u8]) -> Result<NAPTRResults, AresError> {
        panic!("NAPTR parsing not supported");
    }

    /// Obtain a `NAPTRResults` from the response to a NAPTR lookup.
    #[cfg(not(feature = "old-cares"))]
    pub fn parse_from(data: &[u8]) -> Result<NAPTRResults, AresError> {
        let mut naptr_reply: *mut c_ares_sys::Struct_ares_naptr_reply =
            ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_naptr_reply(
                data.as_ptr(),
                data.len() as libc::c_int,
                &mut naptr_reply)
        };
        if parse_status != c_ares_sys::ARES_SUCCESS {
            Err(ares_error(parse_status))
        } else {
            let naptr_result = NAPTRResults::new(naptr_reply);
            Ok(naptr_result)
        }
    }

    fn new(
        reply: *mut c_ares_sys::Struct_ares_naptr_reply) -> NAPTRResults {
        NAPTRResults {
            naptr_reply: reply,
            phantom: PhantomData,
        }
    }

    /// Returns an iterator over the `NAPTRResult` values in this
    /// `NAPTRResults`.
    pub fn iter(&self) -> NAPTRResultsIterator {
        NAPTRResultsIterator {
            next: self.naptr_reply,
            phantom: PhantomData,
        }
    }
}

pub struct NAPTRResultsIterator<'a> {
    next: *const c_ares_sys::Struct_ares_naptr_reply,
    phantom: PhantomData<&'a c_ares_sys::Struct_ares_naptr_reply>,
}

impl<'a> Iterator for NAPTRResultsIterator<'a> {
    type Item = NAPTRResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let naptr_reply = self.next;
        if naptr_reply.is_null() {
            None
        } else {
            self.next = unsafe { (*naptr_reply).next };
            let naptr_result = NAPTRResult {
                naptr_reply: naptr_reply,
                phantom: PhantomData,
            };
            Some(naptr_result)
        }
    }
}

impl<'a> IntoIterator for &'a NAPTRResults {
    type Item = NAPTRResult<'a>;
    type IntoIter = NAPTRResultsIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Drop for NAPTRResults {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_data(self.naptr_reply as *mut libc::c_void);
        }
    }
}

unsafe impl Send for NAPTRResults { }
unsafe impl Sync for NAPTRResults { }
unsafe impl<'a> Send for NAPTRResult<'a> { }
unsafe impl<'a> Sync for NAPTRResult<'a> { }
unsafe impl<'a> Send for NAPTRResultsIterator<'a> { }
unsafe impl<'a> Sync for NAPTRResultsIterator<'a> { }

impl<'a> NAPTRResult<'a> {
    /// Returns the flags in this `NAPTRResult`.
    pub fn flags(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr(
                (*self.naptr_reply).flags as *const libc::c_char);
            str::from_utf8(c_str.to_bytes()).unwrap()
        }
    }

    /// Returns the service name in this `NAPTRResult`.
    pub fn service_name(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr(
                (*self.naptr_reply).service as *const libc::c_char);
            str::from_utf8(c_str.to_bytes()).unwrap()
        }
    }

    /// Returns the regular expression in this `NAPTRResult`.
    pub fn reg_exp(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr(
                (*self.naptr_reply).regexp as *const libc::c_char);
            str::from_utf8(c_str.to_bytes()).unwrap()
        }
    }

    /// Returns the replacement pattern in this `NAPTRResult`.
    pub fn replacement_pattern(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr((*self.naptr_reply).replacement);
            str::from_utf8(c_str.to_bytes()).unwrap()
        }
    }

    /// Returns the order value in this `NAPTRResult`.
    pub fn order(&self) -> u16 {
        unsafe { (*self.naptr_reply).order }
    }

    /// Returns the preference value in this `NAPTRResult`.
    pub fn preference(&self) -> u16 {
        unsafe { (*self.naptr_reply).preference }
    }
}

pub unsafe extern "C" fn query_naptr_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<NAPTRResults, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        NAPTRResults::parse_from(data)
    };
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}
