extern crate c_ares_sys;
extern crate libc;

use std::ffi::CStr;
use std::marker::PhantomData;
use std::mem;
use std::net::Ipv4Addr;
use std::ptr;
use std::slice;
use std::str;

use error::AresError;
use types::hostent;
use utils::ares_error;

/// The result of a successful A lookup.
pub struct AResults {
    hostent: *mut hostent,
    phantom: PhantomData<hostent>,
}

/// The contents of a single A record.
pub struct AResult<'a> {
    h_addr: *const libc::c_char,
    phantom: PhantomData<&'a hostent>,
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
        unsafe {
            let c_str = CStr::from_ptr((*self.hostent).h_name);
            str::from_utf8_unchecked(c_str.to_bytes())
        }
    }

    /// Returns an iterator over the `AResult` values in this `AResults`.
    pub fn iter(&self) -> AResultsIterator {
        AResultsIterator {
            next: unsafe { (*self.hostent).h_addr_list as *const *const _ },
            phantom: PhantomData,
        }
    }
}

pub struct AResultsIterator<'a> {
    next: *const *const libc::c_char,
    phantom: PhantomData<&'a hostent>,
}

impl<'a> Iterator for AResultsIterator<'a> {
    type Item = AResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let h_addr = unsafe { *self.next };
        if h_addr.is_null() {
            None
        } else {
            self.next = unsafe { self.next.offset(1) };
            let a_result = AResult {
                h_addr: h_addr,
                phantom: PhantomData,
            };
            Some(a_result)
        }
    }
}

impl<'a> IntoIterator for &'a AResults {
    type Item = AResult<'a>;
    type IntoIter = AResultsIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
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
unsafe impl<'a> Send for AResult<'a> { }
unsafe impl<'a> Sync for AResult<'a> { }
unsafe impl<'a> Send for AResultsIterator<'a> { }
unsafe impl<'a> Sync for AResultsIterator<'a> { }

impl<'a> AResult<'a> {
    /// Returns the IPv4 address in this `AResult`.
    pub fn ipv4_addr(&self) -> Ipv4Addr {
        unsafe {
            Ipv4Addr::new(
                *self.h_addr as u8,
                *self.h_addr.offset(1) as u8,
                *self.h_addr.offset(2) as u8,
                *self.h_addr.offset(3) as u8)
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
