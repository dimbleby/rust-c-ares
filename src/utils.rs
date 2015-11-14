extern crate c_ares_sys;
extern crate libc;

use ctypes;
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
        ctypes::AF_INET => Some(AddressFamily::INET),
        ctypes::AF_INET6 => Some(AddressFamily::INET6),
        _ => None,
    }
}

// Get the u32 value from an Ipv4Addr.
fn ipv4_as_value(ipv4: &Ipv4Addr) -> u32 {
    ipv4.octets()
        .iter()
        .fold(0, |v, &o| (v << 8) | o as u32)
        .to_be()
}

// Get an in_addr from an Ipv4Addr.
#[cfg(unix)]
pub fn ipv4_as_in_addr(ipv4: &Ipv4Addr) -> ctypes::in_addr {
    ctypes::in_addr { s_addr: ipv4_as_value(ipv4) }
}

#[cfg(windows)]
pub fn ipv4_as_in_addr(ipv4: &Ipv4Addr) -> ctypes::in_addr {
    ctypes::in_addr { S_un: ipv4_as_value(ipv4) }
}

// Get an in6_addr from an Ipv6Addr.
pub fn ipv6_as_in6_addr(ipv6: &Ipv6Addr) -> ctypes::in6_addr {
    let segments = ipv6.segments();
    let mut in6_addr: ctypes::in6_addr = unsafe { mem::uninitialized() };
    in6_addr.s6_addr[0] = (segments[0] >> 8) as u8;
    in6_addr.s6_addr[1] = segments[0] as u8;
    in6_addr.s6_addr[2] = (segments[1] >> 8) as u8;
    in6_addr.s6_addr[3] = segments[1] as u8;
    in6_addr.s6_addr[4] = (segments[2] >> 8) as u8;
    in6_addr.s6_addr[5] = segments[2] as u8;
    in6_addr.s6_addr[6] = (segments[3] >> 8) as u8;
    in6_addr.s6_addr[7] = segments[3] as u8;
    in6_addr.s6_addr[8] = (segments[4] >> 8) as u8;
    in6_addr.s6_addr[9] = segments[4] as u8;
    in6_addr.s6_addr[10] = (segments[5] >> 8) as u8;
    in6_addr.s6_addr[11] = segments[5] as u8;
    in6_addr.s6_addr[12] = (segments[6] >> 8) as u8;
    in6_addr.s6_addr[13] = segments[6] as u8;
    in6_addr.s6_addr[14] = (segments[7] >> 8) as u8;
    in6_addr.s6_addr[15] = segments[7] as u8;
    in6_addr
}

// Get a sockaddr_in from a SocketAddrV4.
pub fn socket_addrv4_as_sockaddr_in(
    sock_v4: &SocketAddrV4) -> ctypes::sockaddr_in {
    let in_addr = ipv4_as_in_addr(sock_v4.ip());
    ctypes::sockaddr_in {
        sin_family: ctypes::AF_INET as ctypes::sa_family_t,
        sin_port: sock_v4.port().to_be(),
        sin_addr: in_addr,
        sin_zero: [0; 8],
    }
}

// Get a sockaddr_in6 from a SocketAddrV6.
pub fn socket_addrv6_as_sockaddr_in6(
    sock_v6: &SocketAddrV6) -> ctypes::sockaddr_in6 {
    let in6_addr = ipv6_as_in6_addr(sock_v6.ip());
    ctypes::sockaddr_in6 {
        sin6_family: ctypes::AF_INET6 as ctypes::sa_family_t,
        sin6_port: sock_v6.port().to_be(),
        sin6_addr: in6_addr,
        sin6_flowinfo: sock_v6.flowinfo().to_be(),
        sin6_scope_id: sock_v6.scope_id().to_be(),
    }
}
