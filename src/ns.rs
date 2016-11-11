use std::fmt;
use std::os::raw::{
    c_int,
    c_uchar,
    c_void,
};
use std::ptr;
use std::slice;

use c_ares_sys;
use c_types;
use itertools::Itertools;

use error::Error;
use hostent::{
    HasHostent,
    HostAliasResultsIter,
    HostentOwned,
};

/// The result of a successful NS lookup.
#[derive(Debug)]
pub struct NSResults {
    hostent: HostentOwned,
}

impl NSResults {
    /// Obtain an `NSResults` from the response to an NS lookup.
    pub fn parse_from(data: &[u8]) -> Result<NSResults, Error> {
        let mut hostent: *mut c_types::hostent = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_ns_reply(
                data.as_ptr(),
                data.len() as c_int,
                &mut hostent as *mut _ as *mut *mut c_ares_sys::hostent)
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
        write!(fmt, "Aliases: [{}]", aliases)?;
        Ok(())
    }
}

pub unsafe extern "C" fn query_ns_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int)
    where F: FnOnce(Result<NSResults, Error>) + Send + 'static {
    let result = if status == c_ares_sys::ARES_SUCCESS {
        let data = slice::from_raw_parts(abuf, alen as usize);
        NSResults::parse_from(data)
    } else {
        Err(Error::from(status))
    };
    let handler = Box::from_raw(arg as *mut F);
    handler(result);
}
