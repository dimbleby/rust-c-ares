extern crate c_ares_sys;
extern crate libc;

use std::ffi::CStr;
use std::marker::PhantomData;
use std::mem;
use std::net::Ipv4Addr;
use std::ptr;
use std::slice;
use std::str;

use types::{
    AresError,
    hostent,
};
use utils::ares_error;

/// The result of a successful lookup for an A record.
pub struct AResults {
    hostent: *mut hostent,
}

impl AResults {
    /// Obtain an `AResults` from the response to an A lookup.
    pub fn parse_from(data: &[u8]) -> Result<AResults, AresError> {
        let mut hostent: *mut hostent = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_a_reply(
                data.as_ptr(),
                data.len() as libc::c_int,
                &mut hostent as *mut *mut _ as *mut *mut c_ares_sys::Struct_hostent,
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
        }
    }

    /// Get the hostname from this `AResults`.
    pub fn hostname(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr((*self.hostent).h_name);
            str::from_utf8_unchecked(c_str.to_bytes())
        }
    }

    /// Returns an iterator over the `Ipv4Address` values in this `AResults`.
    pub fn iter(&self) -> AResultsIterator {
        AResultsIterator {
            next: unsafe { (*self.hostent).h_addr_list },
            phantom: PhantomData,
        }
    }
}

pub struct AResultsIterator<'a> {
    next: *mut *mut libc::c_char,
    phantom: PhantomData<&'a AResults>,
}

impl<'a> Iterator for AResultsIterator<'a> {
    type Item = Ipv4Addr;
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let h_addr = *self.next;
            if h_addr.is_null() {
                None
            } else {
                self.next = self.next.offset(1);
                let ip_addr = Ipv4Addr::new(
                    *h_addr as u8,
                    *h_addr.offset(1) as u8,
                    *h_addr.offset(2) as u8,
                    *h_addr.offset(3) as u8);
                Some(ip_addr)
            }
        }
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
