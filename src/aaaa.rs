extern crate c_ares_sys;
extern crate libc;

use std::marker::PhantomData;
use std::net::Ipv6Addr;
use std::ptr;

use types::{
    AresError,
    hostent,
};
use utils::ares_error;

/// The result of a successful lookup for an AAAA record.
pub struct AAAAResult {
    hostent: *mut hostent,
}

impl AAAAResult {
    fn new(hostent: *mut hostent) -> AAAAResult {
        AAAAResult {
            hostent: hostent,
        }
    }

    /// Returns an iterator over the `Ipv6Address` values in this `AResult`.
    pub fn iter(&self) -> AAAAResultIterator {
        AAAAResultIterator {
            next: unsafe { (*self.hostent).h_addr_list },
            phantom: PhantomData,
        }
    }
}

pub struct AAAAResultIntoIterator {
    next: *mut *mut libc::c_char,

    // Access to the IP addresses is all through the `next` pointer, but we
    // need to keep the AAAAResult around so that this points to valid memory.
    #[allow(dead_code)]
    a_result: AAAAResult,
}

pub struct AAAAResultIterator<'a> {
    next: *mut *mut libc::c_char,

    // We need the phantom data to make sure that the `next` pointer remains
    // valid through the lifetime of this structure.
    phantom: PhantomData<&'a AAAAResult>,
}

impl IntoIterator for AAAAResult {
    type Item = Ipv6Addr;
    type IntoIter = AAAAResultIntoIterator;

    fn into_iter(self) -> Self::IntoIter {
        AAAAResultIntoIterator {
            next: unsafe { (*self.hostent).h_addr_list },
            a_result: self,
        }
    }
}

impl<'a> IntoIterator for &'a AAAAResult {
    type Item = Ipv6Addr;
    type IntoIter = AAAAResultIterator<'a>;

    fn into_iter(self) -> Self::IntoIter {
        AAAAResultIterator {
            next: unsafe { (*self.hostent).h_addr_list },
            phantom: PhantomData,
        }
    }
}

unsafe fn ipv6_addr_from_ptr(h_addr: *mut libc::c_char) -> Ipv6Addr {
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

impl Iterator for AAAAResultIntoIterator {
    type Item = Ipv6Addr;
    fn next(&mut self) -> Option<Ipv6Addr> {
        unsafe {
            let h_addr = *(self.next);
            if h_addr.is_null() {
                None
            } else {
                self.next = self.next.offset(1);
                let ip_addr = ipv6_addr_from_ptr(h_addr);
                Some(ip_addr)
            }
        }
    }
}

impl<'a> Iterator for AAAAResultIterator<'a> {
    type Item = Ipv6Addr;
    fn next(&mut self) -> Option<Ipv6Addr> {
        unsafe {
            let h_addr = *(self.next);
            if h_addr.is_null() {
                None
            } else {
                self.next = self.next.offset(1);
                let ip_addr = ipv6_addr_from_ptr(h_addr);
                Some(ip_addr)
            }
        }
    }
}

impl Drop for AAAAResult {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_hostent(
                self.hostent as *mut c_ares_sys::Struct_hostent);
        }
    }
}

/// Parse the response to an AAAA lookup.
///
/// Users typically won't need to call this function - it's an internal utility
/// that is made public just in case someone finds a use for it.
pub fn parse_aaaa_result(data: &[u8]) -> Result<AAAAResult, AresError> {
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
        let result = AAAAResult::new(hostent);
        Ok(result)
    }
}
