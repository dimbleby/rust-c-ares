extern crate c_ares_sys;
extern crate libc;

use std::fmt;

use c_types;

use error::AresError;
use hostent::{
    HasHostent,
    HostAddressResultsIter,
    HostAliasResultsIter,
    HostentBorrowed,
};
use utils::ares_error;

/// The result of a successful host lookup.
#[derive(Clone, Copy, Debug)]
pub struct HostResults<'a> {
    hostent: HostentBorrowed<'a>,
}

impl<'a> HostResults<'a> {
    fn new(hostent: &'a c_types::hostent) -> HostResults {
        HostResults {
            hostent: HostentBorrowed::new(hostent),
        }
    }

    /// Returns the hostname from this `HostResults`.
    pub fn hostname(&self) -> &str {
        self.hostent.hostname()
    }

    /// Returns an iterator over the `HostAddressResult` values in this
    /// `HostResults`.
    pub fn addresses(&self) -> HostAddressResultsIter {
        self.hostent.addresses()
    }

    /// Returns an iterator over the `HostAliasResult` values in this
    /// `HostResults`.
    pub fn aliases(&self) -> HostAliasResultsIter {
        self.hostent.aliases()
    }
}

impl<'a> fmt::Display for HostResults<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.hostent.display(fmt)
    }
}

unsafe impl<'a> Send for HostResults<'a> { }
unsafe impl<'a> Sync for HostResults<'a> { }

pub unsafe extern "C" fn get_host_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    hostent: *mut c_ares_sys::Struct_hostent)
    where F: FnOnce(Result<HostResults, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let hostent_ref = &*(hostent as *mut c_types::hostent);
        let host_results = HostResults::new(hostent_ref);
        Ok(host_results)
    };
    let handler = Box::from_raw(arg as *mut F);
    handler(result);
}
