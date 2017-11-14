use std::fmt;
use std::os::raw::{c_int, c_uchar, c_void};
use std::ptr;
use std::slice;

use c_ares_sys;
use c_types;
use itertools::Itertools;

use error::{Error, Result};
use hostent::{HasHostent, HostAliasResultsIter, HostentOwned};
use panic;

/// The result of a successful NS lookup.
#[derive(Debug)]
pub struct NSResults {
    hostent: HostentOwned,
}

impl NSResults {
    /// Obtain an `NSResults` from the response to an NS lookup.
    pub fn parse_from(data: &[u8]) -> Result<NSResults> {
        let mut hostent: *mut c_types::hostent = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_ns_reply(data.as_ptr(), data.len() as c_int, &mut hostent)
        };
        if parse_status == c_ares_sys::ARES_SUCCESS {
            let result = NSResults::new(hostent);
            Ok(result)
        } else {
            Err(Error::from(parse_status))
        }
    }

    fn new(hostent: *mut c_types::hostent) -> NSResults {
        NSResults {
            hostent: HostentOwned::new(hostent),
        }
    }

    /// Returns the hostname from this `NSResults`.
    pub fn hostname(&self) -> &str {
        self.hostent.hostname()
    }

    /// Returns an iterator over the host aliases in this `NSResults`.
    pub fn aliases(&self) -> HostAliasResultsIter {
        self.hostent.aliases()
    }
}

impl fmt::Display for NSResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Hostname: {}, ", self.hostname())?;
        let aliases = self.aliases().format(", ");
        write!(fmt, "Aliases: [{}]", aliases)
    }
}

pub unsafe extern "C" fn query_ns_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<NSResults>) + Send + 'static,
{
    ares_callback!(arg as *mut F, status, abuf, alen, NSResults::parse_from);
}
