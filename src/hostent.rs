extern crate c_ares_sys;
extern crate libc;

use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::net::{
    Ipv4Addr,
    Ipv6Addr,
};
use std::ptr;
use std::str;

use types::{
    AddressFamily,
    IpAddr,
};
use utils::address_family;

#[repr(C)]
#[derive(Debug)]
#[allow(raw_pointer_derive)]
pub struct hostent {
    pub h_name: *mut libc::c_char,
    pub h_aliases: *mut *mut libc::c_char,
    pub h_addrtype: libc::c_int,
    pub h_length: libc::c_int,
    pub h_addr_list: *mut *mut libc::c_char,
}

impl hostent {
    pub fn hostname(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr(self.h_name);
            str::from_utf8_unchecked(c_str.to_bytes())
        }
    }

    pub fn addresses(&self) -> HostAddressResultsIterator {
        match address_family(self.h_addrtype) {
            Some(family) => HostAddressResultsIterator {
                family: family,
                next: self.h_addr_list as *const *const _,
                phantom: PhantomData,
            },
            None => HostAddressResultsIterator {
                family: AddressFamily::INET,
                next: ptr::null_mut(),
                phantom: PhantomData,
            }
        }
    }

    pub fn aliases(&self) -> HostAliasResultsIterator {
        HostAliasResultsIterator {
            next: self.h_aliases as *const *const _,
            phantom: PhantomData,
        }
    }
}

impl fmt::Display for hostent {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
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

/// An alias, as retrieved from a host lookup.
#[derive(Debug)]
#[allow(raw_pointer_derive)]
pub struct HostAliasResult<'a> {
    h_alias: *const libc::c_char,
    phantom: PhantomData<&'a hostent>,
}

/// An address, as retrieved from a host lookup.
#[derive(Debug)]
#[allow(raw_pointer_derive)]
pub struct HostAddressResult<'a> {
    family: AddressFamily,
    h_addr: *const libc::c_char,
    phantom: PhantomData<&'a hostent>,
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
                let ipv6 = self.ipv6_addr();
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

    fn ipv6_addr(&self) -> Ipv6Addr {
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

#[derive(Debug)]
#[allow(raw_pointer_derive)]
pub struct HostAddressResultsIterator<'a> {
    family: AddressFamily,
    next: *const *const libc::c_char,
    phantom: PhantomData<&'a hostent>,
}

impl<'a> Iterator for HostAddressResultsIterator<'a> {
    type Item = HostAddressResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let h_addr = unsafe { *self.next };
        if h_addr.is_null() {
            None
        } else {
            self.next = unsafe { self.next.offset(1) };
            let addr_result = HostAddressResult {
                family: self.family,
                h_addr: h_addr,
                phantom: PhantomData,
            };
            Some(addr_result)
        }
    }
}

unsafe impl<'a> Send for HostAddressResultsIterator<'a> { }
unsafe impl<'a> Sync for HostAddressResultsIterator<'a> { }

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

#[derive(Debug)]
#[allow(raw_pointer_derive)]
pub struct HostAliasResultsIterator<'a> {
    next: *const *const libc::c_char,
    phantom: PhantomData<&'a hostent>,
}

impl<'a> Iterator for HostAliasResultsIterator<'a> {
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

unsafe impl<'a> Send for HostAliasResultsIterator<'a> { }
unsafe impl<'a> Sync for HostAliasResultsIterator<'a> { }
