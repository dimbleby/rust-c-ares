use core::ffi::{c_int, c_uchar, c_void};
use std::fmt;
use std::mem;
use std::net::Ipv4Addr;
use std::ptr;
use std::slice;

use itertools::Itertools;

use crate::error::{Error, Result};
use crate::panic;
use crate::types::MAX_ADDRTTLS;
use crate::utils::ipv4_from_in_addr;

/// The result of a successful A lookup.
#[derive(Clone, Copy, Debug)]
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
    pub fn parse_from(data: &[u8]) -> Result<AResults> {
        let mut results: AResults = AResults {
            naddrttls: MAX_ADDRTTLS,
            addrttls: unsafe { mem::MaybeUninit::zeroed().assume_init() },
        };
        let parse_status = unsafe {
            c_ares_sys::ares_parse_a_reply(
                data.as_ptr(),
                data.len() as c_int,
                ptr::null_mut(),
                results.addrttls.as_mut_ptr(),
                ptr::from_mut(&mut results.naddrttls).cast(),
            )
        };
        if parse_status == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            Ok(results)
        } else {
            Err(Error::from(parse_status))
        }
    }

    /// Returns an iterator over the `AResult` values in this `AResults`.
    pub fn iter(&self) -> AResultsIter<'_> {
        AResultsIter {
            addrttls: self.addrttls[0..self.naddrttls].iter(),
        }
    }
}

impl fmt::Display for AResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let results = self.iter().format("}, {");
        write!(fmt, "[{{{results}}}]")
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
        self.addrttls.next().map(|addrttl| AResult { addrttl })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.addrttls.size_hint()
    }
}

impl ExactSizeIterator for AResultsIter<'_> {}
impl std::iter::FusedIterator for AResultsIter<'_> {}

impl<'a> IntoIterator for &'a AResults {
    type Item = AResult<'a>;
    type IntoIter = AResultsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl AResult<'_> {
    /// Returns the IPv4 address in this `AResult`.
    pub fn ipv4(self) -> Ipv4Addr {
        ipv4_from_in_addr(self.addrttl.ipaddr)
    }

    /// Returns the time-to-live in this `AResult`.
    pub fn ttl(self) -> i32 {
        #[allow(clippy::unnecessary_cast)]
        let ttl = self.addrttl.ttl as i32;
        ttl
    }
}

impl fmt::Display for AResult<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "IPv4: {}, ", self.ipv4())?;
        write!(fmt, "TTL: {}", self.ttl())
    }
}

pub(crate) unsafe extern "C" fn query_a_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<AResults>) + Send + 'static,
{
    ares_callback!(arg.cast::<F>(), status, abuf, alen, AResults::parse_from);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_invalid_data() {
        let result = AResults::parse_from(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<AResult>();
        assert_send::<AResults>();
        assert_send::<AResultsIter>();
    }

    #[test]
    fn is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<AResult>();
        assert_sync::<AResults>();
        assert_sync::<AResultsIter>();
    }

    // DNS A response with 2 records: 93.184.216.34 (TTL 300), 93.184.216.35 (TTL 600)
    const TWO_A_RECORDS: &[u8] = &[
        0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78,
        0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0,
        0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04, 0x5d, 0xb8, 0xd8, 0x22,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x58, 0x00, 0x04, 0x5d, 0xb8, 0xd8,
        0x23,
    ];

    #[test]
    fn exact_size_iterator() {
        let results = AResults::parse_from(TWO_A_RECORDS).unwrap();
        let iter = results.iter();
        assert_eq!(iter.len(), 2);
    }

    #[test]
    fn fused_iterator() {
        let results = AResults::parse_from(TWO_A_RECORDS).unwrap();
        let mut iter = results.iter();
        assert!(iter.next().is_some());
        assert!(iter.next().is_some());
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }
}
