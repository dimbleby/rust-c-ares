extern crate c_ares_sys;
extern crate libc;

use error::AresError;
use types::AddressFamily;
use std::mem;
use std::net::{
    Ipv4Addr,
    Ipv6Addr,
    SocketAddrV4,
    SocketAddrV6,
};

// Convert an error code from the library into a more strongly typed AresError.
pub fn ares_error(code: libc::c_int) -> AresError {
    match code {
        c_ares_sys::ARES_ENODATA => AresError::ENODATA,
        c_ares_sys::ARES_EFORMERR => AresError::EFORMERR,
        c_ares_sys::ARES_ESERVFAIL => AresError::ESERVFAIL,
        c_ares_sys::ARES_ENOTFOUND => AresError::ENOTFOUND,
        c_ares_sys::ARES_ENOTIMP => AresError::ENOTIMP,
        c_ares_sys::ARES_EREFUSED => AresError::EREFUSED,
        c_ares_sys::ARES_EBADQUERY => AresError::EBADQUERY,
        c_ares_sys::ARES_EBADNAME => AresError::EBADNAME,
        c_ares_sys::ARES_EBADFAMILY => AresError::EBADFAMILY,
        c_ares_sys::ARES_EBADRESP => AresError::EBADRESP,
        c_ares_sys::ARES_ECONNREFUSED => AresError::ECONNREFUSED,
        c_ares_sys::ARES_ETIMEOUT => AresError::ETIMEOUT,
        c_ares_sys::ARES_EOF => AresError::EOF,
        c_ares_sys::ARES_EFILE => AresError::EFILE,
        c_ares_sys::ARES_ENOMEM => AresError::ENOMEM,
        c_ares_sys::ARES_EDESTRUCTION => AresError::EDESTRUCTION,
        c_ares_sys::ARES_EBADSTR => AresError::EBADSTR,
        c_ares_sys::ARES_EBADFLAGS => AresError::EBADFLAGS,
        c_ares_sys::ARES_ENONAME => AresError::ENONAME,
        c_ares_sys::ARES_EBADHINTS => AresError::EBADHINTS,
        c_ares_sys::ARES_ENOTINITIALIZED => AresError::ENOTINITIALIZED,
        c_ares_sys::ARES_ELOADIPHLPAPI => AresError::ELOADIPHLPAPI,
        c_ares_sys::ARES_EADDRGETNETWORKPARAMS =>
            AresError::EADDRGETNETWORKPARAMS,
        c_ares_sys::ARES_ECANCELLED => AresError::ECANCELLED,
        _ => AresError::UNKNOWN,
    }
}

// Convert an address family into a more strongly typed AddressFamily.
pub fn address_family(family: libc::c_int) -> Option<AddressFamily> {
    match family {
        libc::AF_INET => Some(AddressFamily::INET),
        libc::AF_INET6 => Some(AddressFamily::INET6),
        _ => None,
    }
}

// Get an in_addr from an Ipv4Addr.
pub fn ipv4_as_in_addr(ipv4: &Ipv4Addr) -> &libc::in_addr {
    unsafe { mem::transmute(ipv4) }
}

// Get an in6_addr from an Ipv6Addr.
pub fn ipv6_as_in6_addr(ipv6: &Ipv6Addr) -> &libc::in6_addr {
    unsafe { mem::transmute(ipv6) }
}

// Get a sockaddr_in from a SocketAddrV4.
pub fn socket_addrv4_as_sockaddr_in(
    sock_v4: &SocketAddrV4) -> &libc::sockaddr_in {
    unsafe { mem::transmute(sock_v4) }
}

// Get a sockaddr_in6 from a SocketAddrV6.
pub fn socket_addrv6_as_sockaddr_in6(
    sock_v6: &SocketAddrV6) -> &libc::sockaddr_in6 {
    unsafe { mem::transmute(sock_v6) }
}
