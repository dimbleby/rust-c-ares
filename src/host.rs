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
    pub fn hostname(self) -> &'a str {
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

impl fmt::Display for HostResults<'_> {
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
        let result = if status == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            let host_results = HostResults::new(unsafe { &*hostent });
            Ok(host_results)
        } else {
            Err(Error::from(status))
        };
        let handler = unsafe { Box::from_raw(arg.cast::<F>()) };
        handler(result);
    });
}
