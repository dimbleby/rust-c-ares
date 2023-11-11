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
