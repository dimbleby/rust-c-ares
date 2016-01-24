extern crate c_ares_sys;
extern crate libc;

use std::fmt;
use std::mem;
use std::net::Ipv6Addr;
use std::ptr;
use std::slice;

use error::AresError;
use types::MAX_ADDRTTLS;
use utils::{
    ares_error,
    ipv6_address_from_bytes,
};

/// The result of a successful AAAA lookup.
pub struct AAAAResults {
    naddr6ttls: usize,
    addr6ttls: [c_ares_sys::Struct_ares_addr6ttl; MAX_ADDRTTLS],
}

/// The contents of a single AAAA record.
#[derive(Clone, Copy)]
pub struct AAAAResult<'a> {
    addr6ttl: &'a c_ares_sys::Struct_ares_addr6ttl,
}

impl AAAAResults {
    /// Obtain an `AAAAResults` from the response to an AAAA lookup.
    pub fn parse_from(data: &[u8]) -> Result<AAAAResults, AresError> {
        let mut results: AAAAResults = AAAAResults {
            naddr6ttls: MAX_ADDRTTLS,
            addr6ttls: unsafe { mem::uninitialized() },
        };
        let parse_status = unsafe {
            c_ares_sys::ares_parse_aaaa_reply(
                data.as_ptr(),
                data.len() as libc::c_int,
                ptr::null_mut(),
                results.addr6ttls.as_mut_ptr(),
                &mut results.naddr6ttls as *mut _ as *mut libc::c_int)
        };
        if parse_status != c_ares_sys::ARES_SUCCESS {
            Err(ares_error(parse_status))
        } else {
            Ok(results)
        }
    }

    /// Returns an iterator over the `AAAAResult` values in this `AAAAResults`.
    pub fn iter(&self) -> AAAAResultsIter {
        AAAAResultsIter {
            next: 0,
            results: self,
        }
    }
}

impl fmt::Display for AAAAResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(fmt, "["));
        let mut first = true;
        for a_result in self {
            let prefix = if first { "" } else { ", " };
            first = false;
            try!(write!(fmt, "{}{{{}}}", prefix, a_result));
        }
        try!(write!(fmt, "]"));
        Ok(())
    }
}

/// Iterator of `AAAAResult`s.
#[derive(Clone, Copy)]
pub struct AAAAResultsIter<'a> {
    next: usize,
    results: &'a AAAAResults,
}

impl<'a> Iterator for AAAAResultsIter<'a> {
    type Item = AAAAResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let next = self.next;
        if next >= self.results.naddr6ttls {
            None
        } else {
            self.next = next + 1;
            let a_result = AAAAResult {
                addr6ttl: &self.results.addr6ttls[next],
            };
            Some(a_result)
        }
    }
}

impl<'a> IntoIterator for &'a AAAAResults {
    type Item = AAAAResult<'a>;
    type IntoIter = AAAAResultsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> AAAAResult<'a> {
    /// Returns the IPv6 address in this 'AAAAResult'.
    pub fn ipv6(&self) -> Ipv6Addr {
        let bytes = &self.addr6ttl.ip6addr._S6_un._bindgen_data_;
        ipv6_address_from_bytes(bytes)
    }

    /// Returns the time-to-live in this 'AAAAResult'.
    pub fn ttl(&self) -> i32 {
        self.addr6ttl.ttl as i32
    }
}

impl<'a> fmt::Display for AAAAResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(fmt, "IPv6: {}, ", self.ipv6()));
        try!(write!(fmt, "TTL: {}, ", self.ttl()));
        Ok(())
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
    let handler = Box::from_raw(arg as *mut F);
    handler(result);
}
