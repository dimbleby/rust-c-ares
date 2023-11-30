use crate::ffi::ares_socket_t;
use std::os::raw::c_int;

// Library initialization flags
pub const ARES_LIB_INIT_NONE: c_int = 0;
pub const ARES_LIB_INIT_WIN32: c_int = 1;
pub const ARES_LIB_INIT_ALL: c_int = ARES_LIB_INIT_WIN32;

// Flag values
pub const ARES_FLAG_USEVC: c_int = 1;
pub const ARES_FLAG_PRIMARY: c_int = 1 << 1;
pub const ARES_FLAG_IGNTC: c_int = 1 << 2;
pub const ARES_FLAG_NORECURSE: c_int = 1 << 3;
pub const ARES_FLAG_STAYOPEN: c_int = 1 << 4;
pub const ARES_FLAG_NOSEARCH: c_int = 1 << 5;
pub const ARES_FLAG_NOALIASES: c_int = 1 << 6;
pub const ARES_FLAG_NOCHECKRESP: c_int = 1 << 7;
pub const ARES_FLAG_EDNS: c_int = 1 << 8;

// Option mask values
pub const ARES_OPT_FLAGS: c_int = 1;
pub const ARES_OPT_TIMEOUT: c_int = 1 << 1;
pub const ARES_OPT_TRIES: c_int = 1 << 2;
pub const ARES_OPT_NDOTS: c_int = 1 << 3;
pub const ARES_OPT_UDP_PORT: c_int = 1 << 4;
pub const ARES_OPT_TCP_PORT: c_int = 1 << 5;
pub const ARES_OPT_SERVERS: c_int = 1 << 6;
pub const ARES_OPT_DOMAINS: c_int = 1 << 7;
pub const ARES_OPT_LOOKUPS: c_int = 1 << 8;
pub const ARES_OPT_SOCK_STATE_CB: c_int = 1 << 9;
pub const ARES_OPT_SORTLIST: c_int = 1 << 10;
pub const ARES_OPT_SOCK_SNDBUF: c_int = 1 << 11;
pub const ARES_OPT_SOCK_RCVBUF: c_int = 1 << 12;
pub const ARES_OPT_TIMEOUTMS: c_int = 1 << 13;
pub const ARES_OPT_ROTATE: c_int = 1 << 14;
pub const ARES_OPT_EDNSPSZ: c_int = 1 << 15;
pub const ARES_OPT_NOROTATE: c_int = 1 << 16;
pub const ARES_OPT_RESOLVCONF: c_int = 1 << 17;
pub const ARES_OPT_HOSTS_FILE: c_int = 1 << 18;
pub const ARES_OPT_UDP_MAX_QUERIES: c_int = 1 << 19;
pub const ARES_OPT_MAXTIMEOUTMS: c_int = 1 << 20;
pub const ARES_OPT_QUERY_CACHE: c_int = 1 << 21;

// Flags for nameinfo queries
pub const ARES_NI_NOFQDN: c_int = 1;
pub const ARES_NI_NUMERICHOST: c_int = 1 << 1;
pub const ARES_NI_NAMEREQD: c_int = 1 << 2;
pub const ARES_NI_NUMERICSERV: c_int = 1 << 3;
pub const ARES_NI_DGRAM: c_int = 1 << 4;
pub const ARES_NI_TCP: c_int = 0;
pub const ARES_NI_UDP: c_int = ARES_NI_DGRAM;
pub const ARES_NI_SCTP: c_int = 1 << 5;
pub const ARES_NI_DCCP: c_int = 1 << 6;
pub const ARES_NI_NUMERICSCOPE: c_int = 1 << 7;
pub const ARES_NI_LOOKUPHOST: c_int = 1 << 8;
pub const ARES_NI_LOOKUPSERVICE: c_int = 1 << 9;
pub const ARES_NI_IDN: c_int = 1 << 10;
pub const ARES_NI_IDN_ALLOW_UNASSIGNED: c_int = 1 << 11;
pub const ARES_NI_IDN_USE_STD3_ASCII_RULES: c_int = 1 << 12;

// A non-existent file descriptor
#[cfg(windows)]
pub const ARES_SOCKET_BAD: ares_socket_t = !0;
#[cfg(unix)]
pub const ARES_SOCKET_BAD: ares_socket_t = -1;

// ares_getsock() can return info about this many sockets
pub const ARES_GETSOCK_MAXNUM: usize = 16;
