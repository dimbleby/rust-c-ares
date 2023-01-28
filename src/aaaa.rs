use std::fmt;
use std::mem;
use std::net::Ipv6Addr;
use std::os::raw::{c_int, c_uchar, c_void};
use std::ptr;
use std::slice;

use itertools::Itertools;

use crate::error::{Error, Result};
use crate::panic;
use crate::types::MAX_ADDRTTLS;

/// The result of a successful AAAA lookup.
#[derive(Clone, Copy)]
pub struct AAAAResults {
    naddr6ttls: usize,
    addr6ttls: [c_ares_sys::ares_addr6ttl; MAX_ADDRTTLS],
}

/// The contents of a single AAAA record.
#[derive(Clone, Copy)]
pub struct AAAAResult<'a> {
    addr6ttl: &'a c_ares_sys::ares_addr6ttl,
}

impl AAAAResults {
    /// Obtain an `AAAAResults` from the response to an AAAA lookup.
    pub fn parse_from(data: &[u8]) -> Result<AAAAResults> {
        let mut results: AAAAResults = AAAAResults {
            naddr6ttls: MAX_ADDRTTLS,
            addr6ttls: unsafe { mem::MaybeUninit::zeroed().assume_init() },
        };
        let parse_status = unsafe {
            c_ares_sys::ares_parse_aaaa_reply(
                data.as_ptr(),
                data.len() as c_int,
                ptr::null_mut(),
                results.addr6ttls.as_mut_ptr(),
                &mut results.naddr6ttls as *mut _ as *mut c_int,
            )
        };
        if parse_status == c_ares_sys::ARES_SUCCESS {
            Ok(results)
        } else {
            Err(Error::from(parse_status))
        }
    }

    /// Returns an iterator over the `AAAAResult` values in this `AAAAResults`.
    pub fn iter(&self) -> AAAAResultsIter {
        AAAAResultsIter {
            addr6ttls: self.addr6ttls[0..self.naddr6ttls].iter(),
        }
    }
}

impl fmt::Display for AAAAResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let results = self.iter().format("}, {");
        write!(fmt, "[{{{}}}]", results)
    }
}

/// Iterator of `AAAAResult`s.
#[derive(Clone)]
pub struct AAAAResultsIter<'a> {
    addr6ttls: slice::Iter<'a, c_ares_sys::ares_addr6ttl>,
}

impl<'a> Iterator for AAAAResultsIter<'a> {
    type Item = AAAAResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        self.addr6ttls
            .next()
            .map(|addr6ttl| AAAAResult { addr6ttl })
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
    /// Returns the IPv6 address in this `AAAAResult`.
    pub fn ipv6(self) -> Ipv6Addr {
        let bytes = unsafe { self.addr6ttl.ip6addr._S6_un._S6_u8 };
        Ipv6Addr::from(bytes)
    }

    /// Returns the time-to-live in this `AAAAResult`.
    pub fn ttl(self) -> i32 {
        #[allow(clippy::unnecessary_cast)]
        let ttl = self.addr6ttl.ttl as i32;
        ttl
    }
}

impl<'a> fmt::Display for AAAAResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "IPv6: {}, ", self.ipv6())?;
        write!(fmt, "TTL: {}", self.ttl())
    }
}

pub(crate) unsafe extern "C" fn query_aaaa_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<AAAAResults>) + Send + 'static,
{
    ares_callback!(arg as *mut F, status, abuf, alen, AAAAResults::parse_from);
}
