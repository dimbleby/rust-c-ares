use core::ffi::{c_int, c_uchar, c_void};
use std::fmt;
use std::mem;
use std::net::Ipv6Addr;
use std::ptr;
use std::slice;

use itertools::Itertools;

use crate::error::{Error, Result};
use crate::panic;
use crate::types::MAX_ADDRTTLS;

/// The result of a successful AAAA lookup.
#[derive(Clone, Copy, Debug)]
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
                ptr::from_mut(&mut results.naddr6ttls).cast(),
            )
        };
        if parse_status == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            Ok(results)
        } else {
            Err(Error::from(parse_status))
        }
    }

    /// Returns an iterator over the `AAAAResult` values in this `AAAAResults`.
    pub fn iter(&self) -> AAAAResultsIter<'_> {
        AAAAResultsIter {
            addr6ttls: self.addr6ttls[0..self.naddr6ttls].iter(),
        }
    }
}

impl fmt::Display for AAAAResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let results = self.iter().format("}, {");
        write!(fmt, "[{{{results}}}]")
    }
}

/// Iterator of `AAAAResult`s.
#[derive(Clone, Debug)]
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

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.addr6ttls.size_hint()
    }
}

impl ExactSizeIterator for AAAAResultsIter<'_> {}
impl std::iter::FusedIterator for AAAAResultsIter<'_> {}

impl<'a> IntoIterator for &'a AAAAResults {
    type Item = AAAAResult<'a>;
    type IntoIter = AAAAResultsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl fmt::Debug for AAAAResult<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AAAAResult")
            .field("ipv6", &self.ipv6())
            .field("ttl", &self.ttl())
            .finish()
    }
}

impl AAAAResult<'_> {
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

impl fmt::Display for AAAAResult<'_> {
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
    ares_callback!(arg.cast::<F>(), status, abuf, alen, AAAAResults::parse_from);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_invalid_data() {
        let result = AAAAResults::parse_from(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<AAAAResult>();
        assert_send::<AAAAResults>();
        assert_send::<AAAAResultsIter>();
    }

    #[test]
    fn is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<AAAAResult>();
        assert_sync::<AAAAResults>();
        assert_sync::<AAAAResultsIter>();
    }

    // DNS AAAA response with 1 record: 2001:db8::1 (TTL 300)
    const ONE_AAAA_RECORD: &[u8] = &[
        0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78,
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x10, 0x20, 0x01, 0x0d, 0xb8,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    ];

    #[test]
    fn exact_size_iterator() {
        let results = AAAAResults::parse_from(ONE_AAAA_RECORD).unwrap();
        let iter = results.iter();
        assert_eq!(iter.len(), 1);
    }

    #[test]
    fn fused_iterator() {
        let results = AAAAResults::parse_from(ONE_AAAA_RECORD).unwrap();
        let mut iter = results.iter();
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }

    #[test]
    fn debug_aaaa_result() {
        let results = AAAAResults::parse_from(ONE_AAAA_RECORD).unwrap();
        let result = results.iter().next().unwrap();
        let debug = format!("{:?}", result);
        assert!(debug.contains("AAAAResult"));
        assert!(debug.contains("2001:db8::1"));
        assert!(debug.contains("300"));
    }

    #[test]
    fn debug_aaaa_results_iter() {
        let results = AAAAResults::parse_from(ONE_AAAA_RECORD).unwrap();
        let iter = results.iter();
        let debug = format!("{:?}", iter);
        assert!(debug.contains("AAAAResultsIter"));
    }
}
