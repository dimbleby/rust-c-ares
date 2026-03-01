/// The platform-specific file descriptor / socket type.  That is, either a `RawFd` or a
/// `RawSocket`.
pub type Socket = c_ares_sys::ares_socket_t;

/// An invalid socket / file descriptor.  Use this to represent 'no action' when calling
/// `process_fd()` on a channel.
pub const SOCKET_BAD: Socket = c_ares_sys::ARES_SOCKET_BAD;

/// Address families.
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
pub enum AddressFamily {
    /// IPv4.
    INET = c_types::AF_INET as isize,

    /// IPv6.
    INET6 = c_types::AF_INET6 as isize,

    /// Unspecified.
    UNSPEC = c_types::AF_UNSPEC as isize,
}

// See arpa/nameser.h
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
#[allow(clippy::upper_case_acronyms)]
pub enum QueryType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    NAPTR = 35,
    URI = 256,
    CAA = 257,
}

// See arpa/nameser.h
#[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
pub enum DnsClass {
    IN = 1,
}

pub const MAX_ADDRTTLS: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn socket_bad_is_defined() {
        let _bad = SOCKET_BAD;
    }

    #[test]
    fn address_family_values() {
        assert_ne!(AddressFamily::INET as isize, AddressFamily::INET6 as isize);
        assert_ne!(AddressFamily::INET as isize, AddressFamily::UNSPEC as isize);
        assert_ne!(
            AddressFamily::INET6 as isize,
            AddressFamily::UNSPEC as isize
        );
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn address_family_clone_copy() {
        let af = AddressFamily::INET;
        let cloned = af.clone();
        let copied = af;
        assert_eq!(af, cloned);
        assert_eq!(af, copied);
    }

    #[test]
    fn address_family_debug() {
        let af = AddressFamily::INET6;
        let debug = format!("{:?}", af);
        assert!(debug.contains("INET6"));
    }

    #[test]
    fn address_family_eq_hash() {
        let mut set = HashSet::new();
        set.insert(AddressFamily::INET);
        set.insert(AddressFamily::INET6);
        set.insert(AddressFamily::INET);
        assert_eq!(set.len(), 2);
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn address_family_ord() {
        let families = [
            AddressFamily::INET,
            AddressFamily::INET6,
            AddressFamily::UNSPEC,
        ];
        let mut sorted = families.clone();
        sorted.sort();
        assert_eq!(sorted.len(), 3);
    }
}
