extern crate c_ares_sys;
extern crate libc;

use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::net::{
    Ipv4Addr,
    Ipv6Addr,
};
use std::str;

use c_types;
use ip::IpAddr;

use types::AddressFamily;
use utils::address_family;

#[allow(raw_pointer_derive)]
#[derive(Debug)]
pub struct HostentOwned {
    inner: *mut c_types::hostent,
    phantom: PhantomData<c_types::hostent>,
}

impl HostentOwned {
    pub fn new(hostent: *mut c_types::hostent) -> HostentOwned {
        HostentOwned {
            inner: hostent,
            phantom: PhantomData,
        }
    }
}

impl Drop for HostentOwned {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_hostent(
                self.inner as *mut c_ares_sys::Struct_hostent);
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct HostentBorrowed<'a> {
    inner: &'a c_types::hostent,
}

impl<'a> HostentBorrowed<'a> {
    pub fn new(hostent: &c_types::hostent) -> HostentBorrowed {
        HostentBorrowed {
            inner: hostent,
        }
    }
}

pub trait HasHostent {
    fn hostent(&self) -> &c_types::hostent;

    fn hostname(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr(self.hostent().h_name);
            str::from_utf8_unchecked(c_str.to_bytes())
        }
    }

    fn addresses(&self) -> HostAddressResultsIter {
        HostAddressResultsIter {
            family: address_family(self.hostent().h_addrtype as libc::c_int),
            next: self.hostent().h_addr_list as *const *const _,
            phantom: PhantomData,
        }
    }

    fn aliases(&self) -> HostAliasResultsIter {
        HostAliasResultsIter {
            next: self.hostent().h_aliases as *const *const _,
            phantom: PhantomData,
        }
    }

    fn display(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        try!(write!(fmt, "Hostname: {}, ", self.hostname()));
        try!(write!(fmt, "Addresses: ["));
        let mut first = true;
        for host_addr in self.addresses() {
            let prefix = if first { "" } else { ", " };
            first = false;
            try!(write!(fmt, "{}{}", prefix, host_addr));
        }
        try!(write!(fmt, "], "));
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

impl HasHostent for HostentOwned {
    fn hostent(&self) -> &c_types::hostent {
        unsafe { &*self.inner }
    }
}

impl<'a> HasHostent for HostentBorrowed<'a> {
    fn hostent(&self) -> &c_types::hostent {
        self.inner
    }
}

unsafe impl Send for HostentOwned { }
unsafe impl Sync for HostentOwned { }

unsafe impl<'a> Send for HostentBorrowed<'a> { }
unsafe impl<'a> Sync for HostentBorrowed<'a> { }

/// An alias, as retrieved from a host lookup.
#[derive(Clone, Copy, Debug)]
#[allow(raw_pointer_derive)]
pub struct HostAliasResult<'a> {
    h_alias: *const libc::c_char,
    phantom: PhantomData<&'a c_types::hostent>,
}

/// An address, as retrieved from a host lookup.
#[derive(Clone, Copy, Debug)]
#[allow(raw_pointer_derive)]
pub struct HostAddressResult<'a> {
    family: AddressFamily,
    h_addr: *const libc::c_char,
    phantom: PhantomData<&'a c_types::hostent>,
}

impl<'a> HostAddressResult<'a> {
    /// Returns the IP address in this `HostResult`.
    pub fn ip_address(&self) -> IpAddr {
        match self.family {
            AddressFamily::INET => {
                let ipv4 = self.ipv4_address();
                IpAddr::V4(ipv4)
            },
            AddressFamily::INET6 => {
                let ipv6 = self.ipv6_address();
                IpAddr::V6(ipv6)
            },
        }
    }

    fn ipv4_address(&self) -> Ipv4Addr {
        let h_addr = self.h_addr;
        unsafe {
            Ipv4Addr::new(
                *h_addr as u8,
                *h_addr.offset(1) as u8,
                *h_addr.offset(2) as u8,
                *h_addr.offset(3) as u8)
        }
    }

    fn ipv6_address(&self) -> Ipv6Addr {
        let h_addr = self.h_addr;
        unsafe {
            Ipv6Addr::new(
                ((*h_addr as u16) << 8) + *h_addr.offset(1) as u16,
                ((*h_addr.offset(2) as u16) << 8) + *h_addr.offset(3) as u16,
                ((*h_addr.offset(4) as u16) << 8) + *h_addr.offset(5) as u16,
                ((*h_addr.offset(6) as u16) << 8) + *h_addr.offset(7) as u16,
                ((*h_addr.offset(8) as u16) << 8) + *h_addr.offset(9) as u16,
                ((*h_addr.offset(10) as u16) << 8) + *h_addr.offset(11) as u16,
                ((*h_addr.offset(12) as u16) << 8) + *h_addr.offset(13) as u16,
                ((*h_addr.offset(14) as u16) << 8) + *h_addr.offset(15) as u16)
        }
    }
}

impl<'a> fmt::Display for HostAddressResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.ip_address().fmt(fmt)
    }
}

unsafe impl<'a> Send for HostAddressResult<'a> { }
unsafe impl<'a> Sync for HostAddressResult<'a> { }

/// Iterator of `HostAddressResult`s.
#[derive(Clone, Copy, Debug)]
#[allow(raw_pointer_derive)]
pub struct HostAddressResultsIter<'a> {
    family: Option<AddressFamily>,
    next: *const *const libc::c_char,
    phantom: PhantomData<&'a c_types::hostent>,
}

impl<'a> Iterator for HostAddressResultsIter<'a> {
    type Item = HostAddressResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let h_addr = unsafe { *self.next };
        if h_addr.is_null() {
            None
        } else {
            self.next = unsafe { self.next.offset(1) };
            self.family.map(|family| {
                HostAddressResult {
                    family: family,
                    h_addr: h_addr,
                    phantom: PhantomData,
                }
            })
        }
    }
}

unsafe impl<'a> Send for HostAddressResultsIter<'a> { }
unsafe impl<'a> Sync for HostAddressResultsIter<'a> { }

impl<'a> HostAliasResult<'a> {
    /// Returns the alias in this `HostAliasResult`.
    pub fn alias(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr(self.h_alias);
            str::from_utf8_unchecked(c_str.to_bytes())
        }
    }
}

impl<'a> fmt::Display for HostAliasResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        self.alias().fmt(fmt)
    }
}

unsafe impl<'a> Send for HostAliasResult<'a> { }
unsafe impl<'a> Sync for HostAliasResult<'a> { }

/// Iterator of `HostAliasResult`s.
#[derive(Clone, Copy, Debug)]
#[allow(raw_pointer_derive)]
pub struct HostAliasResultsIter<'a> {
    next: *const *const libc::c_char,
    phantom: PhantomData<&'a c_types::hostent>,
}

impl<'a> Iterator for HostAliasResultsIter<'a> {
    type Item = HostAliasResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let h_alias = unsafe { *self.next };
        if h_alias.is_null() {
            None
        } else {
            self.next = unsafe { self.next.offset(1) };
            let alias_result = HostAliasResult {
                h_alias: h_alias,
                phantom: PhantomData,
            };
            Some(alias_result)
        }
    }
}

unsafe impl<'a> Send for HostAliasResultsIter<'a> { }
unsafe impl<'a> Sync for HostAliasResultsIter<'a> { }
