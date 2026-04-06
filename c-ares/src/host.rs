use core::ffi::{c_char, c_int, c_void};
use std::mem::ManuallyDrop;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::{fmt, ptr, slice};

use itertools::Itertools;

use crate::error::{Error, Result};
use crate::panic;
use crate::types::AddressFamily;
use crate::utils::{address_family, hostname_as_str};

/// The result of a host lookup, wrapping a C `hostent`.
#[derive(Debug)]
pub struct HostResults {
    inner: *mut c_types::hostent,
}

impl HostResults {
    pub(crate) fn new(hostent: *mut c_types::hostent) -> Self {
        HostResults { inner: hostent }
    }

    /// Returns the hostname from this `HostResults`.
    pub fn hostname(&self) -> &str {
        unsafe { hostname_as_str((*self.inner).h_name.cast()) }
    }

    /// Returns an iterator over the `IpAddr` values in this `HostResults`.
    pub fn addresses(&self) -> HostAddressResultsIter<'_> {
        let hostent = unsafe { &*self.inner };
        let addrtype = hostent.h_addrtype as c_types::ADDRESS_FAMILY;
        HostAddressResultsIter {
            family: address_family(addrtype),
            next: unsafe { &*(hostent.h_addr_list.cast()) },
        }
    }

    /// Returns an iterator over the host aliases in this `HostResults`.
    pub fn aliases(&self) -> HostAliasResultsIter<'_> {
        HostAliasResultsIter {
            next: unsafe { &*((*self.inner).h_aliases.cast()) },
        }
    }
}

impl fmt::Display for HostResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Hostname: {}, ", self.hostname())?;
        let addresses = self.addresses().format(", ");
        write!(fmt, "Addresses: [{addresses}], ")?;
        let aliases = self.aliases().format(", ");
        write!(fmt, "Aliases: [{aliases}]")
    }
}

impl Drop for HostResults {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_hostent(self.inner);
        }
    }
}

unsafe impl Send for HostResults {}
unsafe impl Sync for HostResults {}

pub(crate) unsafe extern "C" fn get_host_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    hostent: *mut c_types::hostent,
) where
    F: FnOnce(Result<&HostResults>) + Send + 'static,
{
    let handler = unsafe { Box::from_raw(arg.cast::<F>()) };

    panic::catch(|| {
        if status == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            // We wrap in ManuallyDrop so we don't call ares_free_hostent — c-ares owns this
            // hostent and will free it after we return.
            let host_results = HostResults::new(hostent);
            let host_results = ManuallyDrop::new(host_results);
            handler(Ok(&host_results))
        } else {
            let error = Error::from(status);
            handler(Err(error))
        };
    });
}

// Get an IpAddr from a family and an array of bytes, as found in a `hostent`.
unsafe fn ip_address_from_bytes(family: AddressFamily, h_addr: *const u8) -> Option<IpAddr> {
    match family {
        AddressFamily::INET => {
            let source = unsafe { slice::from_raw_parts(h_addr, 4) };
            let bytes: [u8; 4] = source.try_into().unwrap();
            let ipv4 = Ipv4Addr::from(bytes);
            Some(IpAddr::V4(ipv4))
        }
        AddressFamily::INET6 => {
            let source = unsafe { slice::from_raw_parts(h_addr, 16) };
            let bytes: [u8; 16] = source.try_into().unwrap();
            let ipv6 = Ipv6Addr::from(bytes);
            Some(IpAddr::V6(ipv6))
        }
        _ => None,
    }
}

/// Iterator of `IpAddr`s.
#[derive(Clone, Copy, Debug)]
pub struct HostAddressResultsIter<'a> {
    family: Option<AddressFamily>,
    next: &'a *const c_char,
}

impl Iterator for HostAddressResultsIter<'_> {
    type Item = IpAddr;
    fn next(&mut self) -> Option<Self::Item> {
        let h_addr = *self.next;
        if h_addr.is_null() {
            None
        } else {
            unsafe {
                self.next = &*ptr::from_ref(self.next).add(1);
                self.family
                    .and_then(|family| ip_address_from_bytes(family, h_addr.cast()))
            }
        }
    }
}

unsafe impl Send for HostAddressResultsIter<'_> {}
unsafe impl Sync for HostAddressResultsIter<'_> {}

/// Iterator of `&'a str`s.
#[derive(Clone, Copy, Debug)]
pub struct HostAliasResultsIter<'a> {
    next: &'a *const c_char,
}

impl<'a> Iterator for HostAliasResultsIter<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        let h_alias = *self.next;
        if h_alias.is_null() {
            None
        } else {
            self.next = unsafe { &*ptr::from_ref(self.next).add(1) };
            let string = unsafe { hostname_as_str(h_alias) };
            Some(string)
        }
    }
}

unsafe impl Send for HostAliasResultsIter<'_> {}
unsafe impl Sync for HostAliasResultsIter<'_> {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<HostAddressResultsIter<'_>>();
        assert_send::<HostAliasResultsIter<'_>>();
    }

    #[test]
    fn is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<HostAddressResultsIter<'_>>();
        assert_sync::<HostAliasResultsIter<'_>>();
    }
}
