extern crate c_ares_sys;
extern crate libc;

use std::marker::PhantomData;
use std::mem;
use std::net::Ipv4Addr;
use std::ptr;
use std::slice;

use types::{
    AresError,
    hostent,
};
use utils::ares_error;

/// The result of a successful lookup for an A record.
pub struct AResult {
    hostent: *mut hostent,
}

impl AResult {
    /// Obtain an `AResult` from the response to an A lookup.
    pub fn parse_from(data: &[u8]) -> Result<AResult, AresError> {
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
            let result = AResult::new(hostent);
            Ok(result)
        }
    }

    fn new(hostent: *mut hostent) -> AResult {
        AResult {
            hostent: hostent,
        }
    }

    /// Returns an iterator over the `Ipv4Address` values in this `AResult`.
    pub fn iter(&self) -> AResultIterator {
        AResultIterator {
            next: unsafe { (*self.hostent).h_addr_list },
            phantom: PhantomData,
        }
    }
}

pub struct AResultIntoIterator {
    next: *mut *mut libc::c_char,

    // Access to the IP addresses is all through the `next` pointer, but we
    // need to keep the AResult around so that this points to valid memory.
    #[allow(dead_code)]
    a_result: AResult,
}

pub struct AResultIterator<'a> {
    next: *mut *mut libc::c_char,

    // We need the phantom data to make sure that the `next` pointer remains
    // valid through the lifetime of this structure.
    phantom: PhantomData<&'a AResult>,
}

impl IntoIterator for AResult {
    type Item = Ipv4Addr;
    type IntoIter = AResultIntoIterator;

    fn into_iter(self) -> Self::IntoIter {
        AResultIntoIterator {
            next: unsafe { (*self.hostent).h_addr_list },
            a_result: self,
        }
    }
}

impl<'a> IntoIterator for &'a AResult {
    type Item = Ipv4Addr;
    type IntoIter = AResultIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        AResultIterator {
            next: unsafe { (*self.hostent).h_addr_list },
            phantom: PhantomData,
        }
    }
}

unsafe fn ipv4_addr_from_ptr(h_addr: *mut libc::c_char) -> Ipv4Addr {
    Ipv4Addr::new(
        *h_addr as u8,
        *h_addr.offset(1) as u8,
        *h_addr.offset(2) as u8,
        *h_addr.offset(3) as u8)
}

impl Iterator for AResultIntoIterator {
    type Item = Ipv4Addr;
    fn next(&mut self) -> Option<Ipv4Addr> {
        unsafe {
            let h_addr = *(self.next);
            if h_addr.is_null() {
                None
            } else {
                self.next = self.next.offset(1);
                let ip_addr = ipv4_addr_from_ptr(h_addr);
                Some(ip_addr)
            }
        }
    }
}

impl<'a> Iterator for AResultIterator<'a> {
    type Item = Ipv4Addr;
    fn next(&mut self) -> Option<Ipv4Addr> {
        unsafe {
            let h_addr = *(self.next);
            if h_addr.is_null() {
                None
            } else {
                self.next = self.next.offset(1);
                let ip_addr = ipv4_addr_from_ptr(h_addr);
                Some(ip_addr)
            }
        }
    }
}

impl Drop for AResult {
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
    where F: FnOnce(Result<AResult, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        AResult::parse_from(data)
    };
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}
