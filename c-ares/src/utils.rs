use crate::error::{Error, Result};
use crate::string::{AresBuf, AresString};
use crate::types::AddressFamily;
use core::ffi::{c_char, c_int};
use std::ffi::CStr;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::str;

// Convert an address family into a more strongly typed AddressFamily.
pub fn address_family(family: c_types::ADDRESS_FAMILY) -> Option<AddressFamily> {
    match family {
        c_types::AF_INET => Some(AddressFamily::INET),
        c_types::AF_INET6 => Some(AddressFamily::INET6),
        c_types::AF_UNSPEC => Some(AddressFamily::UNSPEC),
        _ => None,
    }
}

// Get an in_addr from an Ipv4Addr.
#[cfg(unix)]
pub fn ipv4_as_in_addr(ipv4: Ipv4Addr) -> c_types::in_addr {
    c_types::in_addr {
        s_addr: u32::from(ipv4).to_be(),
    }
}

#[cfg(windows)]
pub fn ipv4_as_in_addr(ipv4: Ipv4Addr) -> c_types::in_addr {
    let octets = ipv4.octets();
    let mut in_addr: c_types::in_addr = unsafe { mem::zeroed() };
    in_addr.S_un.S_un_b.s_b1 = octets[0];
    in_addr.S_un.S_un_b.s_b2 = octets[1];
    in_addr.S_un.S_un_b.s_b3 = octets[2];
    in_addr.S_un.S_un_b.s_b4 = octets[3];
    in_addr
}

// Get an Ipv4Addr from an in_addr.
#[cfg(unix)]
pub fn ipv4_from_in_addr(in_addr: c_types::in_addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from_be(in_addr.s_addr))
}

#[cfg(windows)]
pub fn ipv4_from_in_addr(in_addr: c_types::in_addr) -> Ipv4Addr {
    let bytes = unsafe { in_addr.S_un.S_un_b };
    Ipv4Addr::new(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4)
}

// Get an in6_addr from an Ipv6Addr.
#[cfg(unix)]
pub fn ipv6_as_in6_addr(ipv6: &Ipv6Addr) -> c_types::in6_addr {
    let octets = ipv6.octets();
    let mut in6_addr: c_types::in6_addr = unsafe { mem::zeroed() };
    in6_addr.s6_addr.copy_from_slice(&octets);
    in6_addr
}

#[cfg(windows)]
pub fn ipv6_as_in6_addr(ipv6: &Ipv6Addr) -> c_types::in6_addr {
    let octets = ipv6.octets();
    let mut in6_addr: c_types::in6_addr = unsafe { mem::zeroed() };
    unsafe { in6_addr.u.Byte.copy_from_slice(&octets) }
    in6_addr
}

// Get a sockaddr_in from a SocketAddrV4.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd",
))]
pub fn socket_addrv4_as_sockaddr_in(sock_v4: &SocketAddrV4) -> c_types::sockaddr_in {
    let in_addr = ipv4_as_in_addr(*sock_v4.ip());
    c_types::sockaddr_in {
        sin_len: mem::size_of::<c_types::sockaddr_in>() as u8,
        sin_family: c_types::AF_INET as c_types::sa_family_t,
        sin_port: sock_v4.port().to_be(),
        sin_addr: in_addr,
        sin_zero: [0; 8],
    }
}

#[cfg(not(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd",
)))]
pub fn socket_addrv4_as_sockaddr_in(sock_v4: &SocketAddrV4) -> c_types::sockaddr_in {
    let in_addr = ipv4_as_in_addr(*sock_v4.ip());
    c_types::sockaddr_in {
        sin_family: c_types::AF_INET as c_types::sa_family_t,
        sin_port: sock_v4.port().to_be(),
        sin_addr: in_addr,
        sin_zero: [0; 8],
    }
}

// Get a sockaddr_in6 from a SocketAddrV6.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd",
))]
pub fn socket_addrv6_as_sockaddr_in6(sock_v6: &SocketAddrV6) -> c_types::sockaddr_in6 {
    let in6_addr = ipv6_as_in6_addr(sock_v6.ip());
    c_types::sockaddr_in6 {
        sin6_len: mem::size_of::<c_types::sockaddr_in6>() as u8,
        sin6_family: c_types::AF_INET6 as c_types::sa_family_t,
        sin6_port: sock_v6.port().to_be(),
        sin6_addr: in6_addr,
        sin6_flowinfo: sock_v6.flowinfo(),
        sin6_scope_id: sock_v6.scope_id(),
    }
}

#[cfg(all(
    unix,
    not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd",
    ))
))]
pub fn socket_addrv6_as_sockaddr_in6(sock_v6: &SocketAddrV6) -> c_types::sockaddr_in6 {
    let in6_addr = ipv6_as_in6_addr(sock_v6.ip());
    c_types::sockaddr_in6 {
        sin6_family: c_types::AF_INET6 as c_types::sa_family_t,
        sin6_port: sock_v6.port().to_be(),
        sin6_addr: in6_addr,
        sin6_flowinfo: sock_v6.flowinfo(),
        sin6_scope_id: sock_v6.scope_id(),
    }
}

#[cfg(windows)]
pub fn socket_addrv6_as_sockaddr_in6(sock_v6: &SocketAddrV6) -> c_types::sockaddr_in6 {
    let mut sockaddr_in6: c_types::sockaddr_in6 = unsafe { mem::zeroed() };
    sockaddr_in6.sin6_family = c_types::AF_INET6 as c_types::sa_family_t;
    sockaddr_in6.sin6_port = sock_v6.port().to_be();
    sockaddr_in6.sin6_addr = ipv6_as_in6_addr(sock_v6.ip());
    sockaddr_in6.sin6_flowinfo = sock_v6.flowinfo();
    sockaddr_in6.Anonymous.sin6_scope_id = sock_v6.scope_id();
    sockaddr_in6
}

pub unsafe fn c_string_as_str_unchecked<'a>(c_str: *const c_char) -> &'a str {
    let bytes = unsafe { CStr::from_ptr(c_str) }.to_bytes();
    unsafe { str::from_utf8_unchecked(bytes) }
}

#[cfg(not(cares1_30))]
pub unsafe fn c_string_as_str_checked<'a>(c_str: *const c_char) -> &'a str {
    let c_str = unsafe { CStr::from_ptr(c_str) };
    c_str.to_str().unwrap()
}

pub unsafe fn hostname_as_str<'a>(hostname: *const c_char) -> &'a str {
    unsafe { c_string_as_str_unchecked(hostname) }
}

#[cfg(not(cares1_30))]
pub unsafe fn dns_string_as_str<'a>(hostname: *const c_char) -> &'a str {
    unsafe { c_string_as_str_checked(hostname) }
}

#[cfg(cares1_30)]
pub unsafe fn dns_string_as_str<'a>(hostname: *const c_char) -> &'a str {
    unsafe { c_string_as_str_unchecked(hostname) }
}

/// Helper to convert an `ares_status_t` to our `Result`.
pub fn status_to_result(status: c_ares_sys::ares_status_t) -> Result<()> {
    match Error::try_from(status) {
        Ok(err) => Err(err),
        Err(()) => Ok(()),
    }
}

/// Get the version number of the underlying `c-ares` library.
///
/// The version is returned as both a string and an integer.  The integer is built up as 24bit
/// number, with 8 separate bits used for major number, minor number and patch number.  For
/// example, the version string "1.2.3" is returned as hexadecimal number 0x010203 (decimal 66051).
pub fn version() -> (&'static str, u32) {
    let mut int_version: c_int = 0;
    let str_version = unsafe {
        let ptr = c_ares_sys::ares_version(&mut int_version);
        c_string_as_str_unchecked(ptr)
    };
    (str_version, int_version as u32)
}

/// Whether the underlying `c-ares` library was built with thread safety enabled or not.
///
/// This is unlikely to be of interest to users of this crate.  Our API assumes that c-ares was not
/// built with thread safety, and uses Rust's safety features to prevent errors.
#[cfg(cares1_23)]
pub fn thread_safety() -> bool {
    let safety = unsafe { c_ares_sys::ares_threadsafety() };
    safety != c_ares_sys::ares_bool_t::ARES_FALSE
}

/// Expand a DNS-encoded domain name from a DNS message.
///
/// `encoded` must point within the message buffer `abuf`.  Returns the
/// expanded name and the number of bytes consumed from the encoded input.
pub fn expand_name(encoded: &[u8], abuf: &[u8]) -> Result<(AresString, usize)> {
    let mut s: *mut c_char = std::ptr::null_mut();
    let mut enclen: core::ffi::c_long = 0;
    let status = unsafe {
        c_ares_sys::ares_expand_name(
            encoded.as_ptr(),
            abuf.as_ptr(),
            abuf.len() as c_int,
            &mut s,
            &mut enclen,
        )
    };
    if status != c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
        return Err(Error::from(status));
    }
    Ok((AresString::new(s), enclen as usize))
}

/// Expand a single DNS-encoded string from a DNS message.
///
/// `encoded` must point within the message buffer `abuf`.  Returns the
/// expanded string as bytes and the number of bytes consumed from the encoded
/// input.
pub fn expand_string(encoded: &[u8], abuf: &[u8]) -> Result<(AresBuf, usize)> {
    let mut s: *mut core::ffi::c_uchar = std::ptr::null_mut();
    let mut enclen: core::ffi::c_long = 0;
    let status = unsafe {
        c_ares_sys::ares_expand_string(
            encoded.as_ptr(),
            abuf.as_ptr(),
            abuf.len() as c_int,
            &mut s,
            &mut enclen,
        )
    };
    if status != c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
        return Err(Error::from(status));
    }

    // enclen includes the 1-byte length prefix; the decoded data is the rest.
    // We cannot use CStr::from_ptr because the data may contain embedded nulls.
    debug_assert!(enclen >= 1, "ares_expand_string returned enclen < 1 on success");
    let len = (enclen - 1) as usize;
    Ok((AresBuf::new(s, len), enclen as usize))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_returns_string_and_int() {
        let (version_str, version_int) = version();
        assert!(!version_str.is_empty());
        assert!(version_int > 0);
    }

    #[test]
    fn version_string_format() {
        let (version_str, _) = version();
        assert!(version_str.contains('.'));
    }

    #[test]
    fn version_int_format() {
        let (_, version_int) = version();
        assert!(version_int >= 0x010000);
    }

    #[cfg(cares1_23)]
    #[test]
    fn thread_safety_returns_bool() {
        let _safety = thread_safety();
    }

    #[test]
    fn address_family_inet() {
        let result = address_family(c_types::AF_INET);
        assert_eq!(result, Some(AddressFamily::INET));
    }

    #[test]
    fn address_family_inet6() {
        let result = address_family(c_types::AF_INET6);
        assert_eq!(result, Some(AddressFamily::INET6));
    }

    #[test]
    fn address_family_unspec() {
        let result = address_family(c_types::AF_UNSPEC);
        assert_eq!(result, Some(AddressFamily::UNSPEC));
    }

    #[test]
    fn address_family_unknown() {
        // Use an invalid address family value
        let result = address_family(255);
        assert_eq!(result, None);
    }

    #[test]
    fn expand_name_simple() {
        // A minimal DNS-like buffer containing the encoded name
        // "\x07example\x03com\x00" at offset 0.
        let buf: &[u8] = b"\x07example\x03com\x00";
        let (name, enclen) = expand_name(buf, buf).expect("expand_name");
        assert_eq!(&*name, "example.com");
        assert_eq!(enclen, buf.len());
    }

    #[test]
    fn expand_name_invalid() {
        // A truncated buffer should fail
        let buf: &[u8] = b"\x07exam";
        assert!(expand_name(buf, buf).is_err());
    }

    #[test]
    fn expand_string_simple() {
        // A length-prefixed string: \x05hello
        let buf: &[u8] = b"\x05hello";
        let (data, enclen) = expand_string(buf, buf).expect("expand_string");
        assert_eq!(&*data, b"hello");
        assert_eq!(enclen, buf.len());
    }

    #[test]
    fn expand_string_invalid() {
        // Length prefix says 10 but only 3 bytes follow
        let buf: &[u8] = b"\x0aabc";
        assert!(expand_string(buf, buf).is_err());
    }

    #[test]
    fn expand_string_embedded_null() {
        // Binary data with an embedded null: length 4, then "a\x00bc"
        let buf: &[u8] = b"\x04a\x00bc";
        let (data, enclen) = expand_string(buf, buf).expect("expand_string");
        assert_eq!(&*data, b"a\x00bc");
        assert_eq!(data.len(), 4);
        assert_eq!(enclen, buf.len());
    }
}
