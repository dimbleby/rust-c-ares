use std::ffi::CStr;
use std::fmt;
use std::os::raw::{c_int, c_void};

use crate::error::{Error, Result};
use crate::hostent::{HasHostent, HostAddressResultsIter, HostAliasResultsIter, HostentBorrowed};
use crate::panic;

/// The result of a successful host lookup.
#[derive(Clone, Copy)]
pub struct HostResults<'a> {
    hostent: HostentBorrowed<'a>,
}

impl<'a> HostResults<'a> {
    fn new(hostent: &'a c_types::hostent) -> Self {
        HostResults {
            hostent: HostentBorrowed::new(hostent),
        }
    }

    /// Returns the hostname from this `HostResults`.
    ///
    /// In practice this is very likely to be a valid UTF-8 string, but the underlying `c-ares`
    /// library does not guarantee this - so we leave it to users to decide whether they prefer a
    /// fallible conversion, a lossy conversion, or something else altogether.
    pub fn hostname(self) -> &'a CStr {
        self.hostent.hostname()
    }

    /// Returns an iterator over the `IpAddr` values in this `HostResults`.
    pub fn addresses(self) -> HostAddressResultsIter<'a> {
        self.hostent.addresses()
    }

    /// Returns an iterator over the host aliases in this `HostResults`.
    pub fn aliases(self) -> HostAliasResultsIter<'a> {
        self.hostent.aliases()
    }
}

impl<'a> fmt::Display for HostResults<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.hostent.fmt(fmt)
    }
}

pub(crate) unsafe extern "C" fn get_host_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    hostent: *mut c_types::hostent,
) where
    F: FnOnce(Result<HostResults>) + Send + 'static,
{
    panic::catch(|| {
        let result = if status == c_ares_sys::ARES_SUCCESS {
            let host_results = HostResults::new(&*(hostent as *const c_types::hostent));
            Ok(host_results)
        } else {
            Err(Error::from(status))
        };
        let handler = Box::from_raw(arg as *mut F);
        handler(result);
    });
}
