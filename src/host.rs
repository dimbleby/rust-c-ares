extern crate c_ares_sys;
extern crate libc;

use std::fmt;
use std::mem;

use error::AresError;
use hostent::{
    hostent,
    HostAddressResultsIterator,
    HostAliasResultsIterator,
};
use utils::ares_error;

/// The result of a successful host lookup.
#[derive(Debug)]
pub struct HostResults<'a> {
    hostent: &'a hostent,
}

impl<'a> HostResults<'a> {
    fn new(hostent: &'a hostent) -> HostResults {
        HostResults {
            hostent: hostent,
        }
    }

    /// Returns the hostname from this `HostResults`.
    pub fn hostname(&self) -> &str {
        self.hostent.hostname()
    }

    /// Returns an iterator over the `HostAddressResult` values in this
    /// `HostResults`.
    pub fn addresses(&self) -> HostAddressResultsIterator {
        self.hostent.addresses()
    }

    /// Returns an iterator over the `HostAliasResult` values in this
    /// `HostResults`.
    pub fn aliases(&self) -> HostAliasResultsIterator {
        self.hostent.aliases()
    }
}

impl<'a> fmt::Display for HostResults<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.hostent.fmt(fmt)
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
        let hostent_ref = &*(hostent as *mut hostent);
        let host_results = HostResults::new(hostent_ref);
        Ok(host_results)
    };
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}
