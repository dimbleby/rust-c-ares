use std::ffi::CStr;
use std::fmt;
use std::os::raw::{c_int, c_uchar, c_void};
use std::ptr;
use std::slice;

use itertools::Itertools;

use crate::error::{Error, Result};
use crate::hostent::{HasHostent, HostAliasResultsIter, HostentOwned};
use crate::panic;

/// The result of a successful PTR lookup.
#[derive(Debug)]
pub struct PTRResults {
    hostent: HostentOwned,
}

impl PTRResults {
    /// Obtain a `PTRResults` from the response to a PTR lookup.
    pub fn parse_from(data: &[u8]) -> Result<PTRResults> {
        let mut hostent: *mut c_types::hostent = ptr::null_mut();
        let dummy_ip = [0, 0, 0, 0];
        let parse_status = unsafe {
            #[allow(clippy::useless_conversion)]
            c_ares_sys::ares_parse_ptr_reply(
                data.as_ptr(),
                data.len() as c_int,
                dummy_ip.as_ptr().cast(),
                dummy_ip.len() as c_int,
                c_types::AF_INET.into(),
                &mut hostent,
            )
        };
        if parse_status == c_ares_sys::ARES_SUCCESS {
            let result = PTRResults::new(hostent);
            Ok(result)
        } else {
            Err(Error::from(parse_status))
        }
    }

    fn new(hostent: *mut c_types::hostent) -> Self {
        PTRResults {
            hostent: HostentOwned::new(hostent),
        }
    }

    /// Returns the hostname from this `PTRResults`.
    ///
    /// In practice this is very likely to be a valid UTF-8 string, but the underlying `c-ares`
    /// library does not guarantee this - so we leave it to users to decide whether they prefer a
    /// fallible conversion, a lossy conversion, or something else altogether.
    pub fn hostname(&self) -> &CStr {
        self.hostent.hostname()
    }

    /// Returns an iterator over the host aliases in this `PTRResults`.
    pub fn aliases(&self) -> HostAliasResultsIter {
        self.hostent.aliases()
    }
}

impl fmt::Display for PTRResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "Hostname: {}, ",
            self.hostname().to_str().unwrap_or("<not utf8>")
        )?;
        let aliases = self
            .aliases()
            .map(|cstr| cstr.to_str().unwrap_or("<not utf8>"))
            .format(", ");
        write!(fmt, "Aliases: [{aliases}]")
    }
}

pub(crate) unsafe extern "C" fn query_ptr_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<PTRResults>) + Send + 'static,
{
    ares_callback!(arg.cast::<F>(), status, abuf, alen, PTRResults::parse_from);
}
