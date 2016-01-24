extern crate c_ares_sys;

use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{
    c_char,
    c_int,
};
use std::slice;
use std::str;

use c_types;
use ip::IpAddr;

use types::AddressFamily;
use utils::{
    address_family,
    ipv4_address_from_bytes,
    ipv6_address_from_bytes,
};

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
    inner: *const c_types::hostent,
    phantom: PhantomData<&'a c_types::hostent>,
}

impl<'a> HostentBorrowed<'a> {
    pub fn new(hostent: *const c_types::hostent) -> HostentBorrowed<'a> {
        HostentBorrowed {
            inner: hostent,
            phantom: PhantomData,
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
            family: address_family(self.hostent().h_addrtype as c_int),
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
        unsafe { &*self.inner }
    }
}

unsafe impl Send for HostentOwned { }
unsafe impl Sync for HostentOwned { }

unsafe impl<'a> Send for HostentBorrowed<'a> { }
unsafe impl<'a> Sync for HostentBorrowed<'a> { }

/// Iterator of `IpAddr`s.
#[derive(Clone, Copy, Debug)]
pub struct HostAddressResultsIter<'a> {
    family: Option<AddressFamily>,
    next: *const *const c_char,
    phantom: PhantomData<&'a c_types::hostent>,
}

// Get an IpAddr from a family and an array of bytes, as found in a `hostent`.
unsafe fn ip_address_from_bytes(family: AddressFamily, h_addr: *const u8) -> IpAddr {
    match family {
        AddressFamily::INET => {
            let bytes = slice::from_raw_parts(h_addr, 4);
            let ipv4 = ipv4_address_from_bytes(bytes);
            IpAddr::V4(ipv4)
        },
        AddressFamily::INET6 => {
            let bytes = slice::from_raw_parts(h_addr, 16);
            let ipv6 = ipv6_address_from_bytes(bytes);
            IpAddr::V6(ipv6)
        },
    }
}

impl<'a> Iterator for HostAddressResultsIter<'a> {
    type Item = IpAddr;
    fn next(&mut self) -> Option<Self::Item> {
        let h_addr = unsafe { *self.next };
        if h_addr.is_null() {
            None
        } else {
            unsafe {
                self.next = self.next.offset(1);
                self.family.map(|family| ip_address_from_bytes(family, h_addr as *const u8))
            }
        }
    }
}

unsafe impl<'a> Send for HostAddressResultsIter<'a> { }
unsafe impl<'a> Sync for HostAddressResultsIter<'a> { }

/// Iterator of `&'a str`s.
#[derive(Clone, Copy, Debug)]
pub struct HostAliasResultsIter<'a> {
    next: *const *const c_char,
    phantom: PhantomData<&'a c_types::hostent>,
}

impl<'a> Iterator for HostAliasResultsIter<'a> {
    type Item = &'a str;
    fn next(&mut self) -> Option<Self::Item> {
        let h_alias = unsafe { *self.next };
        if h_alias.is_null() {
            None
        } else {
            unsafe {
                self.next = self.next.offset(1);
                let c_str = CStr::from_ptr(h_alias);
                Some(str::from_utf8_unchecked(c_str.to_bytes()))
            }
        }
    }
}

unsafe impl<'a> Send for HostAliasResultsIter<'a> { }
unsafe impl<'a> Sync for HostAliasResultsIter<'a> { }
