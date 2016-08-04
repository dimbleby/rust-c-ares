use std::fmt;
use std::mem;
use std::net::Ipv4Addr;
use std::os::raw::{
    c_int,
    c_uchar,
    c_void,
};
use std::ptr;
use std::slice;

use c_ares_sys;
use itertools::Itertools;

use error::AresError;
use types::MAX_ADDRTTLS;
use utils:: ipv4_from_in_addr;

/// The result of a successful A lookup.
#[derive(Clone, Copy)]
pub struct AResults {
    naddrttls: usize,
    addrttls: [c_ares_sys::ares_addrttl; MAX_ADDRTTLS],
}

/// The contents of a single A record.
#[derive(Clone, Copy)]
pub struct AResult<'a> {
    addrttl: &'a c_ares_sys::ares_addrttl,
}

impl AResults {
    /// Obtain an `AResults` from the response to an A lookup.
    pub fn parse_from(data: &[u8]) -> Result<AResults, AresError> {
        let mut results: AResults = AResults {
            naddrttls: MAX_ADDRTTLS,
            addrttls: unsafe { mem::uninitialized() },
        };
        let parse_status = unsafe {
            c_ares_sys::ares_parse_a_reply(
                data.as_ptr(),
                data.len() as c_int,
                ptr::null_mut(),
                results.addrttls.as_mut_ptr(),
                &mut results.naddrttls as *mut _ as *mut c_int)
        };
        if parse_status == c_ares_sys::ARES_SUCCESS {
            Ok(results)
        } else {
            Err(AresError::from(parse_status))
        }
    }

    /// Returns an iterator over the `AResult` values in this `AResults`.
    pub fn iter(&self) -> AResultsIter {
        AResultsIter { addrttls: self.addrttls[0 .. self.naddrttls].iter() }
    }
}

impl fmt::Display for AResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let results = self.iter().format_default("}, {");
        try!(write!(fmt, "[{{{}}}]", results));
        Ok(())
    }
}

/// Iterator of `AResult`s.
#[derive(Clone)]
pub struct AResultsIter<'a> {
    addrttls: slice::Iter<'a, c_ares_sys::ares_addrttl>,
}

impl<'a> Iterator for AResultsIter<'a> {
    type Item = AResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.addrttls.next().map(|addrttl| AResult { addrttl: addrttl })
    }
}

impl<'a> IntoIterator for &'a AResults {
    type Item = AResult<'a>;
    type IntoIter = AResultsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> AResult<'a> {
    /// Returns the IPv4 address in this `AResult`.
    pub fn ipv4(&self) -> Ipv4Addr {
        ipv4_from_in_addr(&self.addrttl.ipaddr)
    }

    /// Returns the time-to-live in this `AResult`.
    pub fn ttl(&self) -> i32 {
        self.addrttl.ttl as i32
    }
}

impl<'a> fmt::Display for AResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(fmt, "IPv4: {}, ", self.ipv4()));
        try!(write!(fmt, "TTL: {}", self.ttl()));
        Ok(())
    }
}

pub unsafe extern "C" fn query_a_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int)
    where F: FnOnce(Result<AResults, AresError>) + 'static {
    let result = if status == c_ares_sys::ARES_SUCCESS {
        let data = slice::from_raw_parts(abuf, alen as usize);
        AResults::parse_from(data)
    } else {
        Err(AresError::from(status))
    };
    let handler = Box::from_raw(arg as *mut F);
    handler(result);
}
