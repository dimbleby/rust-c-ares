use core::ffi::{c_int, c_void};
use std::fmt;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

use bitflags::bitflags;
use itertools::Itertools;

use crate::error::{Error, Result};
use crate::panic;
use crate::types::AddressFamily;
use crate::utils::{hostname_as_str, ipv4_from_in_addr, ipv6_from_in6_addr, sockaddr_in6_scope_id};

bitflags!(
    /// Flags that may be passed in `AddrInfoHints`.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct AddrInfoFlags: i32 {
        /// The `ares_addrinfo` structure will return canonical names list.
        const CANONNAME = c_ares_sys::ARES_AI_CANONNAME;

        /// The `name` parameter is a numeric host address string.
        const NUMERICHOST = c_ares_sys::ARES_AI_NUMERICHOST;

        /// Return socket addresses suitable for `bind()`.
        const PASSIVE = c_ares_sys::ARES_AI_PASSIVE;

        /// The `service` field will be treated as a numeric value.
        const NUMERICSERV = c_ares_sys::ARES_AI_NUMERICSERV;

        /// If `ai_family` is `AF_INET6`, return IPv4-mapped IPv6 addresses when no IPv6 addresses
        /// are found.
        const V4MAPPED = c_ares_sys::ARES_AI_V4MAPPED;

        /// Used with `V4MAPPED`. Return both IPv6 and IPv4-mapped IPv6 addresses.
        const ALL = c_ares_sys::ARES_AI_ALL;

        /// Only return addresses if a non-loopback address of that family is configured.
        const ADDRCONFIG = c_ares_sys::ARES_AI_ADDRCONFIG;

        /// Result addresses will not be sorted and no connections to resolved addresses will be
        /// attempted.
        const NOSORT = c_ares_sys::ARES_AI_NOSORT;

        /// Read hosts file path from the environment variable `CARES_HOSTS`.
        const ENVHOSTS = c_ares_sys::ARES_AI_ENVHOSTS;
    }
);

/// Hints for an `ares_getaddrinfo()` call, controlling the returned results.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AddrInfoHints {
    /// Flags controlling the query behaviour.
    pub flags: AddrInfoFlags,
    /// Desired address family (`INET`, `INET6`, or `UNSPEC`).
    pub family: Option<AddressFamily>,
    /// Desired socket type. Common values are `libc::SOCK_STREAM` (TCP) and `libc::SOCK_DGRAM`
    /// (UDP). `0` means any type.
    pub socktype: i32,
    /// Desired protocol number. Common values are `libc::IPPROTO_TCP` and `libc::IPPROTO_UDP`.
    /// `0` means any protocol.
    pub protocol: i32,
}

impl Default for AddrInfoFlags {
    fn default() -> Self {
        Self::empty()
    }
}

impl From<&AddrInfoHints> for c_ares_sys::ares_addrinfo_hints {
    fn from(hints: &AddrInfoHints) -> Self {
        c_ares_sys::ares_addrinfo_hints {
            ai_flags: hints.flags.bits(),
            ai_family: hints
                .family
                .map_or(c_types::AF_UNSPEC as c_int, |f| f as c_int),
            ai_socktype: hints.socktype,
            ai_protocol: hints.protocol,
        }
    }
}

/// The result of a successful `get_addrinfo()` call.
///
/// Owns the underlying `ares_addrinfo` pointer and frees it on drop via `ares_freeaddrinfo()`.
pub struct AddrInfoResults {
    addrinfo: *mut c_ares_sys::ares_addrinfo,
}

impl AddrInfoResults {
    pub(crate) fn new(addrinfo: *mut c_ares_sys::ares_addrinfo) -> Self {
        AddrInfoResults { addrinfo }
    }

    /// Returns the official name of the host.
    pub fn name(&self) -> Option<&str> {
        unsafe { (*self.addrinfo).name.as_ref() }.map(|name| unsafe { hostname_as_str(name) })
    }

    /// Returns an iterator over the address nodes in this result.
    pub fn nodes(&self) -> AddrInfoNodeIter<'_> {
        AddrInfoNodeIter {
            next: unsafe { (*self.addrinfo).nodes.as_ref() },
        }
    }

    /// Returns an iterator over the CNAME chain in this result.
    pub fn cnames(&self) -> AddrInfoCNameIter<'_> {
        AddrInfoCNameIter {
            next: unsafe { (*self.addrinfo).cnames.as_ref() },
        }
    }
}

impl fmt::Display for AddrInfoResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        if let Some(name) = self.name() {
            write!(fmt, "Name: {name}, ")?;
        }
        let nodes = self.nodes().format(", ");
        write!(fmt, "Nodes: [{nodes}]")?;
        let cnames: Vec<_> = self.cnames().collect();
        if !cnames.is_empty() {
            let cnames = cnames.iter().format(", ");
            write!(fmt, ", CNames: [{cnames}]")?;
        }
        Ok(())
    }
}

impl fmt::Debug for AddrInfoResults {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddrInfoResults")
            .field("name", &self.name())
            .finish_non_exhaustive()
    }
}

impl Drop for AddrInfoResults {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_freeaddrinfo(self.addrinfo);
        }
    }
}

unsafe impl Send for AddrInfoResults {}
unsafe impl Sync for AddrInfoResults {}

/// A single address node from an `AddrInfoResults`.
#[derive(Clone, Copy)]
pub struct AddrInfoNode<'a> {
    node: &'a c_ares_sys::ares_addrinfo_node,
}

impl AddrInfoNode<'_> {
    /// Returns the TTL for this address record.
    pub fn ttl(&self) -> i32 {
        self.node.ai_ttl
    }

    /// Returns the address family (`AF_INET` or `AF_INET6`).
    pub fn family(&self) -> AddressFamily {
        match self.node.ai_family as c_types::ADDRESS_FAMILY {
            c_types::AF_INET => AddressFamily::INET,
            c_types::AF_INET6 => AddressFamily::INET6,
            _ => AddressFamily::UNSPEC,
        }
    }

    /// Returns the socket type, e.g. `libc::SOCK_STREAM` (TCP) or `libc::SOCK_DGRAM` (UDP).
    /// `0` if unspecified.
    pub fn socktype(&self) -> i32 {
        self.node.ai_socktype
    }

    /// Returns the protocol number, e.g. `libc::IPPROTO_TCP` or `libc::IPPROTO_UDP`.
    /// `0` if unspecified.
    pub fn protocol(&self) -> i32 {
        self.node.ai_protocol
    }

    /// Returns the socket address (IP + port) for this node.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        let addr = self.node.ai_addr;
        if addr.is_null() {
            return None;
        }
        match self.node.ai_family as c_types::ADDRESS_FAMILY {
            c_types::AF_INET => {
                // c-ares allocates the sockaddr with proper alignment for the
                // address family indicated by `ai_family`.
                #[allow(clippy::cast_ptr_alignment)]
                let sa = unsafe { &*(addr.cast::<c_types::sockaddr_in>()) };
                let ip = ipv4_from_in_addr(sa.sin_addr);
                let port = u16::from_be(sa.sin_port);
                Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
            }
            c_types::AF_INET6 => {
                // c-ares allocates the sockaddr with proper alignment for the
                // address family indicated by `ai_family`.
                #[allow(clippy::cast_ptr_alignment)]
                let sa = unsafe { &*(addr.cast::<c_types::sockaddr_in6>()) };
                let ip = ipv6_from_in6_addr(sa.sin6_addr);
                let port = u16::from_be(sa.sin6_port);
                let scope_id = sockaddr_in6_scope_id(sa);
                Some(SocketAddr::V6(SocketAddrV6::new(
                    ip,
                    port,
                    sa.sin6_flowinfo,
                    scope_id,
                )))
            }
            _ => None,
        }
    }

    /// Returns the IP address for this node.
    pub fn ip_addr(&self) -> Option<IpAddr> {
        self.socket_addr().map(|sa| sa.ip())
    }
}

impl fmt::Debug for AddrInfoNode<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddrInfoNode")
            .field("ttl", &self.ttl())
            .field("family", &self.family())
            .field("socktype", &self.socktype())
            .field("protocol", &self.protocol())
            .field("socket_addr", &self.socket_addr())
            .finish()
    }
}

impl fmt::Display for AddrInfoNode<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        if let Some(addr) = self.ip_addr() {
            write!(fmt, "{addr}")?;
        } else {
            write!(fmt, "<unknown>")?;
        }
        write!(fmt, " (ttl: {})", self.ttl())
    }
}

unsafe impl Send for AddrInfoNode<'_> {}
unsafe impl Sync for AddrInfoNode<'_> {}

/// Iterator over the address nodes in an `AddrInfoResults`.
#[derive(Clone)]
pub struct AddrInfoNodeIter<'a> {
    next: Option<&'a c_ares_sys::ares_addrinfo_node>,
}

impl fmt::Debug for AddrInfoNodeIter<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AddrInfoNodeIter").finish_non_exhaustive()
    }
}

impl<'a> Iterator for AddrInfoNodeIter<'a> {
    type Item = AddrInfoNode<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let opt_node = self.next;
        self.next = opt_node.and_then(|node| unsafe { node.ai_next.as_ref() });
        opt_node.map(|node| AddrInfoNode { node })
    }
}

impl std::iter::FusedIterator for AddrInfoNodeIter<'_> {}

unsafe impl Send for AddrInfoNodeIter<'_> {}
unsafe impl Sync for AddrInfoNodeIter<'_> {}

/// A single CNAME record from an `AddrInfoResults`.
#[derive(Clone, Copy, Debug)]
pub struct AddrInfoCName<'a> {
    cname: &'a c_ares_sys::ares_addrinfo_cname,
}

impl AddrInfoCName<'_> {
    /// Returns the TTL for this CNAME record.
    pub fn ttl(&self) -> i32 {
        self.cname.ttl
    }

    /// Returns the alias (the label of the CNAME resource record).
    pub fn alias(&self) -> &str {
        unsafe { hostname_as_str(self.cname.alias) }
    }

    /// Returns the canonical name (the value of the CNAME resource record).
    pub fn name(&self) -> &str {
        unsafe { hostname_as_str(self.cname.name) }
    }
}

impl fmt::Display for AddrInfoCName<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "{} -> {} (ttl: {})",
            self.alias(),
            self.name(),
            self.ttl()
        )
    }
}

unsafe impl Send for AddrInfoCName<'_> {}
unsafe impl Sync for AddrInfoCName<'_> {}

/// Iterator over the CNAME chain in an `AddrInfoResults`.
#[derive(Clone, Debug)]
pub struct AddrInfoCNameIter<'a> {
    next: Option<&'a c_ares_sys::ares_addrinfo_cname>,
}

impl<'a> Iterator for AddrInfoCNameIter<'a> {
    type Item = AddrInfoCName<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let opt_cname = self.next;
        self.next = opt_cname.and_then(|cname| unsafe { cname.next.as_ref() });
        opt_cname.map(|cname| AddrInfoCName { cname })
    }
}

impl std::iter::FusedIterator for AddrInfoCNameIter<'_> {}

unsafe impl Send for AddrInfoCNameIter<'_> {}
unsafe impl Sync for AddrInfoCNameIter<'_> {}

pub(crate) unsafe extern "C" fn get_addrinfo_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    addrinfo: *mut c_ares_sys::ares_addrinfo,
) where
    F: FnOnce(Result<AddrInfoResults>) + Send + 'static,
{
    let result = if status == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
        Ok(AddrInfoResults::new(addrinfo))
    } else {
        Err(Error::from(status))
    };
    let handler = unsafe { Box::from_raw(arg.cast::<F>()) };
    panic::abort_on_panic(|| handler(result));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<AddrInfoResults>();
        assert_send::<AddrInfoNode<'_>>();
        assert_send::<AddrInfoNodeIter<'_>>();
        assert_send::<AddrInfoCName<'_>>();
        assert_send::<AddrInfoCNameIter<'_>>();
    }

    #[test]
    fn is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<AddrInfoResults>();
        assert_sync::<AddrInfoNode<'_>>();
        assert_sync::<AddrInfoNodeIter<'_>>();
        assert_sync::<AddrInfoCName<'_>>();
        assert_sync::<AddrInfoCNameIter<'_>>();
    }

    #[test]
    fn hints_default() {
        let hints = AddrInfoHints::default();
        assert_eq!(hints.flags, AddrInfoFlags::empty());
        assert_eq!(hints.family, None);
        assert_eq!(hints.socktype, 0);
        assert_eq!(hints.protocol, 0);
    }

    #[test]
    fn hints_into_raw() {
        let hints = AddrInfoHints {
            flags: AddrInfoFlags::CANONNAME | AddrInfoFlags::NUMERICSERV,
            family: Some(AddressFamily::INET),
            socktype: 1,
            protocol: 6,
        };
        let raw: c_ares_sys::ares_addrinfo_hints = (&hints).into();
        assert_eq!(
            raw.ai_flags,
            (AddrInfoFlags::CANONNAME | AddrInfoFlags::NUMERICSERV).bits()
        );
        assert_eq!(raw.ai_family, AddressFamily::INET as c_int);
        assert_eq!(raw.ai_socktype, 1);
        assert_eq!(raw.ai_protocol, 6);
    }

    #[test]
    fn hints_unspec_family() {
        let hints = AddrInfoHints::default();
        let raw: c_ares_sys::ares_addrinfo_hints = (&hints).into();
        assert_eq!(raw.ai_family, c_types::AF_UNSPEC as c_int);
    }

    #[test]
    fn flags_empty() {
        let flags = AddrInfoFlags::empty();
        assert!(flags.is_empty());
    }

    #[test]
    fn flags_combine() {
        let flags = AddrInfoFlags::CANONNAME | AddrInfoFlags::NOSORT;
        assert!(flags.contains(AddrInfoFlags::CANONNAME));
        assert!(flags.contains(AddrInfoFlags::NOSORT));
        assert!(!flags.contains(AddrInfoFlags::PASSIVE));
    }

    #[test]
    fn flags_debug() {
        let flags = AddrInfoFlags::CANONNAME | AddrInfoFlags::NUMERICHOST;
        let debug = format!("{flags:?}");
        assert!(!debug.is_empty());
    }
}
