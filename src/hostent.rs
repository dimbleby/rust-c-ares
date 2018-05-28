use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::raw::{c_char, c_int};
use std::slice;

use c_ares_sys;
use c_types;
use itertools::Itertools;

use types::AddressFamily;
use utils::address_family;

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
            c_ares_sys::ares_free_hostent(self.inner);
        }
    }
}

#[derive(Clone, Copy)]
pub struct HostentBorrowed<'a> {
    inner: &'a c_types::hostent,
}

impl<'a> HostentBorrowed<'a> {
    pub fn new(hostent: &'a c_types::hostent) -> HostentBorrowed<'a> {
        HostentBorrowed { inner: hostent }
    }
}

pub trait HasHostent {
    fn hostent(&self) -> &c_types::hostent;

    fn hostname(&self) -> &CStr {
        unsafe { CStr::from_ptr(self.hostent().h_name) }
    }

    fn addresses(&self) -> HostAddressResultsIter {
        // h_addrtype is `c_short` on windows, `c_int` on unix.  Tell clippy to
        // allow the identity conversion in the latter case.
        #[cfg_attr(feature = "cargo-clippy", allow(identity_conversion))]
        let addrtype = c_int::from(self.hostent().h_addrtype);
        HostAddressResultsIter {
            family: address_family(addrtype),
            next: unsafe { &*(self.hostent().h_addr_list as *const _) },
        }
    }

    fn aliases(&self) -> HostAliasResultsIter {
        HostAliasResultsIter {
            next: unsafe { &*(self.hostent().h_aliases as *const _) },
        }
    }

    fn display(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "Hostname: {}, ",
            self.hostname().to_str().unwrap_or("<not utf8>")
        )?;
        let addresses = self.addresses().format(", ");
        write!(fmt, "Addresses: [{}]", addresses)?;
        let aliases = self.aliases()
            .map(|cstr| cstr.to_str().unwrap_or("<not utf8>"))
            .format(", ");
        write!(fmt, "Aliases: [{}]", aliases)
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

unsafe impl Send for HostentOwned {}
unsafe impl Sync for HostentOwned {}

unsafe impl<'a> Send for HostentBorrowed<'a> {}
unsafe impl<'a> Sync for HostentBorrowed<'a> {}

/// Iterator of `IpAddr`s.
#[derive(Clone, Copy, Debug)]
pub struct HostAddressResultsIter<'a> {
    family: Option<AddressFamily>,
    next: &'a *const c_char,
}

// Get an IpAddr from a family and an array of bytes, as found in a `hostent`.
unsafe fn ip_address_from_bytes(family: AddressFamily, h_addr: *const u8) -> Option<IpAddr> {
    match family {
        AddressFamily::INET => {
            let source = slice::from_raw_parts(h_addr, 4);
            let mut bytes: [u8; 4] = mem::uninitialized();
            bytes.copy_from_slice(source);
            let ipv4 = Ipv4Addr::from(bytes);
            Some(IpAddr::V4(ipv4))
        }
        AddressFamily::INET6 => {
            let source = slice::from_raw_parts(h_addr, 16);
            let mut bytes: [u8; 16] = mem::uninitialized();
            bytes.copy_from_slice(source);
            let ipv6 = Ipv6Addr::from(bytes);
            Some(IpAddr::V6(ipv6))
        }
        _ => None,
    }
}

impl<'a> Iterator for HostAddressResultsIter<'a> {
    type Item = IpAddr;
    fn next(&mut self) -> Option<Self::Item> {
        let h_addr = *self.next;
        if h_addr.is_null() {
            None
        } else {
            unsafe {
                self.next = &*(self.next as *const *const c_char).offset(1);
                self.family
                    .and_then(|family| ip_address_from_bytes(family, h_addr as *const u8))
            }
        }
    }
}

unsafe impl<'a> Send for HostAddressResultsIter<'a> {}
unsafe impl<'a> Sync for HostAddressResultsIter<'a> {}

/// Iterator of `&'a CStr`s.
///
/// Each item is very likely to be a valid UTF-8 string, but the underlying `c-ares` library does
/// not guarantee this - so we leave it to users to decide whether they prefer a fallible
/// conversion, a lossy conversion, or something else altogether.
#[derive(Clone, Copy, Debug)]
pub struct HostAliasResultsIter<'a> {
    next: &'a *const c_char,
}

impl<'a> Iterator for HostAliasResultsIter<'a> {
    type Item = &'a CStr;
    fn next(&mut self) -> Option<Self::Item> {
        let h_alias = *self.next;
        if h_alias.is_null() {
            None
        } else {
            unsafe {
                self.next = &*(self.next as *const *const c_char).offset(1);
                let c_str = CStr::from_ptr(h_alias);
                Some(c_str)
            }
        }
    }
}

unsafe impl<'a> Send for HostAliasResultsIter<'a> {}
unsafe impl<'a> Sync for HostAliasResultsIter<'a> {}
