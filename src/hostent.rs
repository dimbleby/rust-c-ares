use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::c_char;
use std::{fmt, ptr, slice};

use itertools::Itertools;

use crate::types::AddressFamily;
use crate::utils::{address_family, hostname_as_str};

fn hostname(hostent: &c_types::hostent) -> &str {
    unsafe { hostname_as_str(hostent.h_name.cast()) }
}

fn addresses(hostent: &c_types::hostent) -> HostAddressResultsIter<'_> {
    let addrtype = hostent.h_addrtype as c_types::ADDRESS_FAMILY;
    HostAddressResultsIter {
        family: address_family(addrtype),
        next: unsafe { &*(hostent.h_addr_list.cast()) },
    }
}

fn aliases(hostent: &c_types::hostent) -> HostAliasResultsIter<'_> {
    HostAliasResultsIter {
        next: unsafe { &*(hostent.h_aliases.cast()) },
    }
}

fn display(hostent: &c_types::hostent, fmt: &mut fmt::Formatter) -> fmt::Result {
    write!(fmt, "Hostname: {}, ", hostname(hostent))?;
    let addresses = addresses(hostent).format(", ");
    write!(fmt, "Addresses: [{addresses}], ")?;
    let aliases = aliases(hostent).format(", ");
    write!(fmt, "Aliases: [{aliases}]")
}

pub trait HasHostent<'a>: Sized {
    fn hostent(self) -> &'a c_types::hostent;

    fn hostname(self) -> &'a str {
        let hostent = self.hostent();
        hostname(hostent)
    }

    fn addresses(self) -> HostAddressResultsIter<'a> {
        let hostent = self.hostent();
        addresses(hostent)
    }

    fn aliases(self) -> HostAliasResultsIter<'a> {
        let hostent = self.hostent();
        aliases(hostent)
    }
}

#[derive(Debug)]
pub struct HostentOwned {
    inner: *mut c_types::hostent,
}

impl HostentOwned {
    pub fn new(hostent: *mut c_types::hostent) -> Self {
        HostentOwned { inner: hostent }
    }
}

impl<'a> HasHostent<'a> for &'a HostentOwned {
    fn hostent(self) -> &'a c_types::hostent {
        unsafe { &*self.inner }
    }
}

impl fmt::Display for HostentOwned {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let hostent = self.hostent();
        display(hostent, fmt)
    }
}

impl Drop for HostentOwned {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_hostent(self.inner);
        }
    }
}

unsafe impl Send for HostentOwned {}
unsafe impl Sync for HostentOwned {}

#[derive(Clone, Copy)]
pub struct HostentBorrowed<'a> {
    inner: &'a c_types::hostent,
}

impl<'a> HostentBorrowed<'a> {
    pub fn new(hostent: &'a c_types::hostent) -> Self {
        HostentBorrowed { inner: hostent }
    }
}

impl<'a> HasHostent<'a> for HostentBorrowed<'a> {
    fn hostent(self) -> &'a c_types::hostent {
        self.inner
    }
}

impl fmt::Display for HostentBorrowed<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let hostent = self.hostent();
        display(hostent, fmt)
    }
}

unsafe impl Send for HostentBorrowed<'_> {}
unsafe impl Sync for HostentBorrowed<'_> {}

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
                self.next = &*ptr::from_ref(self.next).offset(1);
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
            self.next = unsafe { &*ptr::from_ref(self.next).offset(1) };
            let string = unsafe { hostname_as_str(h_alias) };
            Some(string)
        }
    }
}

unsafe impl Send for HostAliasResultsIter<'_> {}
unsafe impl Sync for HostAliasResultsIter<'_> {}
