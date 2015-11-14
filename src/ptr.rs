extern crate c_ares_sys;
extern crate libc;

use std::fmt;
use std::marker::PhantomData;
use std::ptr;
use std::slice;

use ctypes;
use error::AresError;
use hostent::{
    hostent,
    HostAliasResultsIterator,
};
use utils::ares_error;

/// The result of a successful PTR lookup.
#[derive(Debug)]
#[allow(raw_pointer_derive)]
pub struct PTRResults {
    hostent: *mut hostent,
    phantom: PhantomData<hostent>,
}

impl PTRResults {
    /// Obtain a `PTRResults` from the response to a PTR lookup.
    pub fn parse_from(data: &[u8]) -> Result<PTRResults, AresError> {
        let mut hostent: *mut hostent = ptr::null_mut();
        let dummy_ip = [0,0,0,0];
        let parse_status = unsafe {
            c_ares_sys::ares_parse_ptr_reply(
                data.as_ptr(),
                data.len() as libc::c_int,
                dummy_ip.as_ptr() as *const libc::c_void,
                dummy_ip.len() as libc::c_int,
                ctypes::AF_INET,
                &mut hostent
                    as *mut *mut _ as *mut *mut c_ares_sys::Struct_hostent)
        };
        if parse_status != c_ares_sys::ARES_SUCCESS {
            Err(ares_error(parse_status))
        } else {
            let result = PTRResults::new(hostent);
            Ok(result)
        }
    }

    fn new(hostent: *mut hostent) -> PTRResults {
        PTRResults {
            hostent: hostent,
            phantom: PhantomData,
        }
    }

    /// Returns the hostname from this `PTRResults`.
    pub fn hostname(&self) -> &str {
        let hostent = unsafe { &*self.hostent };
        hostent.hostname()
    }

    /// Returns an iterator over the `HostAliasResult` values in this
    /// `PTRResults`.
    pub fn aliases(&self) -> HostAliasResultsIterator {
        let hostent = unsafe { &*self.hostent };
        hostent.aliases()
    }
}

impl fmt::Display for PTRResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(fmt, "Hostname: {}, ", self.hostname()));
        try!(write!(fmt, "Aliases: ["));
        let mut first = true;
        for host_alias in self.aliases() {
            let prefix = if first { "" } else { ", " };
            first = false;
            try!(write!(fmt, "{}{}", prefix, host_alias));
        }
        try!(write!(fmt, "]"));
        Ok(())
    }
}

impl Drop for PTRResults {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_hostent(
                self.hostent as *mut c_ares_sys::Struct_hostent);
        }
    }
}

unsafe impl Send for PTRResults { }
unsafe impl Sync for PTRResults { }

pub unsafe extern "C" fn query_ptr_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<PTRResults, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        PTRResults::parse_from(data)
    };
    let handler = Box::from_raw(arg as *mut F);
    handler(result);
}
