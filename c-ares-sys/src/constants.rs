extern crate libc;

use ffi::ares_socket_t;

// Library initialization flags
pub const ARES_LIB_INIT_NONE: libc::c_int = (0);
pub const ARES_LIB_INIT_WIN32: libc::c_int = (1 << 0);
pub const ARES_LIB_INIT_ALL: libc::c_int = (ARES_LIB_INIT_WIN32);

// Error codes
pub const ARES_SUCCESS: libc::c_int = 0;
pub const ARES_ENODATA: libc::c_int = 1;
pub const ARES_EFORMERR: libc::c_int = 2;
pub const ARES_ESERVFAIL: libc::c_int = 3;
pub const ARES_ENOTFOUND: libc::c_int = 4;
pub const ARES_ENOTIMP: libc::c_int = 5;
pub const ARES_EREFUSED: libc::c_int = 6;
pub const ARES_EBADQUERY: libc::c_int = 7;
pub const ARES_EBADNAME: libc::c_int = 8;
pub const ARES_EBADFAMILY: libc::c_int = 9;
pub const ARES_EBADRESP: libc::c_int = 10;
pub const ARES_ECONNREFUSED: libc::c_int = 11;
pub const ARES_ETIMEOUT: libc::c_int = 12;
pub const ARES_EOF: libc::c_int = 13;
pub const ARES_EFILE: libc::c_int = 14;
pub const ARES_ENOMEM: libc::c_int = 15;
pub const ARES_EDESTRUCTION: libc::c_int = 16;
pub const ARES_EBADSTR: libc::c_int = 17;
pub const ARES_EBADFLAGS: libc::c_int = 18;
pub const ARES_ENONAME: libc::c_int = 19;
pub const ARES_EBADHINTS: libc::c_int = 20;
pub const ARES_ENOTINITIALIZED: libc::c_int = 21;
pub const ARES_ELOADIPHLPAPI: libc::c_int = 22;
pub const ARES_EADDRGETNETWORKPARAMS: libc::c_int = 23;
pub const ARES_ECANCELLED: libc::c_int = 24;

// Flag values
pub const ARES_FLAG_USEVC: libc::c_int = (1 << 0);
pub const ARES_FLAG_PRIMARY: libc::c_int = (1 << 1);
pub const ARES_FLAG_IGNTC: libc::c_int = (1 << 2);
pub const ARES_FLAG_NORECURSE: libc::c_int = (1 << 3);
pub const ARES_FLAG_STAYOPEN: libc::c_int = (1 << 4);
pub const ARES_FLAG_NOSEARCH: libc::c_int = (1 << 5);
pub const ARES_FLAG_NOALIASES: libc::c_int = (1 << 6);
pub const ARES_FLAG_NOCHECKRESP: libc::c_int = (1 << 7);
pub const ARES_FLAG_EDNS: libc::c_int = (1 << 8);

// Option mask values
pub const ARES_OPT_FLAGS: libc::c_int = (1 << 0);
pub const ARES_OPT_TIMEOUT: libc::c_int = (1 << 1);
pub const ARES_OPT_TRIES: libc::c_int = (1 << 2);
pub const ARES_OPT_NDOTS: libc::c_int = (1 << 3);
pub const ARES_OPT_UDP_PORT: libc::c_int = (1 << 4);
pub const ARES_OPT_TCP_PORT: libc::c_int = (1 << 5);
pub const ARES_OPT_SERVERS: libc::c_int = (1 << 6);
pub const ARES_OPT_DOMAINS: libc::c_int = (1 << 7);
pub const ARES_OPT_LOOKUPS: libc::c_int = (1 << 8);
pub const ARES_OPT_SOCK_STATE_CB: libc::c_int = (1 << 9);
pub const ARES_OPT_SORTLIST: libc::c_int = (1 << 10);
pub const ARES_OPT_SOCK_SNDBUF: libc::c_int = (1 << 11);
pub const ARES_OPT_SOCK_RCVBUF: libc::c_int = (1 << 12);
pub const ARES_OPT_TIMEOUTMS: libc::c_int = (1 << 13);
pub const ARES_OPT_ROTATE: libc::c_int = (1 << 14);
pub const ARES_OPT_EDNSPSZ: libc::c_int = (1 << 15);

// Flags for nameinfo queries
pub const ARES_NI_NOFQDN: libc::c_int = (1 << 0);
pub const ARES_NI_NUMERICHOST: libc::c_int = (1 << 1);
pub const ARES_NI_NAMEREQD: libc::c_int = (1 << 2);
pub const ARES_NI_NUMERICSERV: libc::c_int = (1 << 3);
pub const ARES_NI_DGRAM: libc::c_int = (1 << 4);
pub const ARES_NI_TCP: libc::c_int = 0;
pub const ARES_NI_UDP: libc::c_int = ARES_NI_DGRAM;
pub const ARES_NI_SCTP: libc::c_int = (1 << 5);
pub const ARES_NI_DCCP: libc::c_int = (1 << 6);
pub const ARES_NI_NUMERICSCOPE: libc::c_int = (1 << 7);
pub const ARES_NI_LOOKUPHOST: libc::c_int = (1 << 8);
pub const ARES_NI_LOOKUPSERVICE: libc::c_int = (1 << 9);
pub const ARES_NI_IDN: libc::c_int = (1 << 10);
pub const ARES_NI_IDN_ALLOW_UNASSIGNED: libc::c_int = (1 << 11);
pub const ARES_NI_IDN_USE_STD3_ASCII_RULES: libc::c_int = (1 << 12);

// A non-existent file descriptor
pub const ARES_SOCKET_BAD: ares_socket_t = -1;

// ares_getsock() can return info about this many sockets
pub const ARES_GETSOCK_MAXNUM: usize = 16;
