extern crate c_ares_sys;
extern crate libc;

use std::ffi::CStr;
use std::marker::PhantomData;
use std::mem;
use std::net::Ipv6Addr;
use std::ptr;
use std::slice;
use std::str;

use types::{
    AresError,
    hostent,
};
use utils::ares_error;

/// The result of a successful lookup for an AAAA record.
pub struct AAAAResults {
    // This pointer is owned by the `AAAAResults`.
    hostent: *mut hostent,
}

/// The contents of a single AAAA record.
pub struct AAAAResult<'a> {
    // This pointer is a reference to a value in an `AAAAResults`.
    h_addr: *mut libc::c_char,
    phantom: PhantomData<&'a AAAAResults>,
}

impl AAAAResults {
    /// Obtain an `AAAAResults` from the response to an AAAA lookup.
    pub fn parse_from(data: &[u8]) -> Result<AAAAResults, AresError> {
        let mut hostent: *mut hostent = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_aaaa_reply(
                data.as_ptr(),
                data.len() as libc::c_int,
                &mut hostent as *mut *mut _ as *mut *mut c_ares_sys::Struct_hostent,
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
        }
    }

    /// Returns the hostname from this `AAAAResults`.
    pub fn hostname(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr((*self.hostent).h_name);
            str::from_utf8_unchecked(c_str.to_bytes())
        }
    }

    /// Returns an iterator over the `AAAAResult` values in this
    /// `AAAAResults`.
    pub fn iter(&self) -> AAAAResultsIterator {
        AAAAResultsIterator {
            next: unsafe { (*self.hostent).h_addr_list },
            phantom: PhantomData,
        }
    }
}

pub struct AAAAResultsIterator<'a> {
    next: *mut *mut libc::c_char,
    phantom: PhantomData<&'a AAAAResults>,
}

impl<'a> Iterator for AAAAResultsIterator<'a> {
    type Item = AAAAResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        unsafe {
            let h_addr = *self.next;
            if h_addr.is_null() {
                None
            } else {
                self.next = self.next.offset(1);
                let aaaa_result = AAAAResult {
                    h_addr: h_addr,
                    phantom: PhantomData,
                };
                Some(aaaa_result)
            }
        }
    }
}

impl<'a> IntoIterator for &'a AAAAResults {
    type Item = AAAAResult<'a>;
    type IntoIter = AAAAResultsIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        AAAAResultsIterator {
            next: unsafe { (*self.hostent).h_addr_list },
            phantom: PhantomData,
        }
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

impl<'a> AAAAResult<'a> {
    /// Returns the IPv6 address in this `AAAAResult`.
    pub fn ipv6_addr(&self) -> Ipv6Addr {
        let h_addr = self.h_addr;
        unsafe {
            Ipv6Addr::new(
                ((*h_addr as u16) << 8) + *h_addr.offset(1) as u16,
                ((*h_addr.offset(2) as u16) << 8) + *h_addr.offset(3) as u16,
                ((*h_addr.offset(4) as u16) << 8) + *h_addr.offset(5) as u16,
                ((*h_addr.offset(6) as u16) << 8) + *h_addr.offset(7) as u16,
                ((*h_addr.offset(8) as u16) << 8) + *h_addr.offset(9) as u16,
                ((*h_addr.offset(10) as u16) << 8) + *h_addr.offset(11) as u16,
                ((*h_addr.offset(12) as u16) << 8) + *h_addr.offset(13) as u16,
                ((*h_addr.offset(14) as u16) << 8) + *h_addr.offset(15) as u16)
        }
    }
}

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
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}
