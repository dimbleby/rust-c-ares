//! A safe wrapper for the [`c-ares`](https://c-ares.org) library.
//!
//! If your `c-ares` is sufficiently recent (version 1.26+) and built with thread safety, it should
//! be quite ergonomic to use this crate directly. See the
//! [`event_thread`](https://github.com/dimbleby/rust-c-ares/tree/main/c-ares/examples/event_thread.rs)
//! example.
//!
//! Otherwise, you will need to manage your own event loop. You may prefer the
//! [`c-ares-resolver`](https://crates.io/crates/c-ares-resolver) crate, which does that for you.
//! That crate also offers a variety of resolvers: using callbacks, using futures, or blocking.
//!
//! Direct usage without the event thread requires you to pay attention to `c-ares` as it tells you
//! which file descriptors it cares about, and to poll for activity on those file descriptors:
//!
//! - Create a `Channel`.
//!
//! - Make queries on the `Channel`.  Queries all take callbacks, which will be called when the
//!   query completes.
//!
//! - Have `c-ares` tell you what file descriptors to listen on for read and / or write events.
//!   You can do this either by providing a callback, which is called whenever the set of
//!   interesting file descriptors changes, or by querying the `Channel` directly either with
//!   `sockets()` or with `fds()`.
//!
//! - Do as `c-ares` asks.  That is, listen for the events that it requests, on the file
//!   descriptors that it cares about.
//!
//! - When a file descriptor becomes readable or writable, call either `process_fd()` or
//!   `process()` on the `Channel` to tell `c-ares` what has happened.
//!
//! - If you have queries pending and don't see events happening, you still need to call either
//!   `process_fd()` or `process()` at some point anyway - to give `c-ares` an opportunity to
//!   process any requests that have timed out.
#![deny(missing_docs)]

#[macro_use]
mod macros;
mod a;
mod aaaa;
mod addrinfo;
mod caa;
mod channel;
mod cname;
#[cfg(cares1_28)]
mod dns;
mod error;
#[cfg(cares1_34)]
mod events;
mod flags;
mod host;
mod mx;
mod nameinfo;
mod naptr;
mod ni_flags;
mod ns;
mod panic;
mod ptr;
mod query;
mod server_state_flags;
mod soa;
mod srv;
mod string;
mod txt;
mod types;
mod uri;
mod utils;

// Re-export public interfaces.
pub use crate::a::{AResult, AResults, AResultsIter};
pub use crate::aaaa::{AAAAResult, AAAAResults, AAAAResultsIter};
pub use crate::addrinfo::{
    AddrInfoCName, AddrInfoCNameIter, AddrInfoFlags, AddrInfoHints, AddrInfoNode, AddrInfoNodeIter,
    AddrInfoResults,
};
pub use crate::caa::{CAAResult, CAAResults, CAAResultsIter};
#[cfg(cares1_29)]
pub use crate::channel::ServerFailoverOptions;
pub use crate::channel::{Channel, Options, Sockets, SocketsIter};
pub use crate::cname::CNameResults;
#[cfg(cares1_28)]
pub use crate::dns::{
    DnsCls, DnsDataType, DnsFlags, DnsOpcode, DnsOptDataType, DnsParseFlags, DnsRcode, DnsRecord,
    DnsRecordType, DnsRr, DnsRrKey, DnsSection, OptParseError, OptValue, parse_opt_value,
};
pub use crate::error::{Error, Result};
#[cfg(cares1_34)]
pub use crate::events::{FdEventFlags, FdEvents, ProcessFlags};
pub use crate::flags::Flags;
pub use crate::host::{HostAddressResultsIter, HostAliasResultsIter, HostResults};
pub use crate::mx::{MXResult, MXResults, MXResultsIter};
pub use crate::nameinfo::NameInfoResult;
pub use crate::naptr::{NAPTRResult, NAPTRResults, NAPTRResultsIter};
pub use crate::ni_flags::NIFlags;
pub use crate::ns::NSResults;
pub use crate::ptr::PTRResults;
#[cfg(cares1_29)]
pub use crate::server_state_flags::ServerStateFlags;
pub use crate::soa::SOAResult;
pub use crate::srv::{SRVResult, SRVResults, SRVResultsIter};
pub use crate::string::{AresBuf, AresString};
pub use crate::txt::{TXTResult, TXTResults, TXTResultsIter};
#[cfg(cares1_26)]
pub use crate::types::EventSys;
pub use crate::types::{AddressFamily, SOCKET_BAD, Socket};
pub use crate::uri::{URIResult, URIResults, URIResultsIter};
#[cfg(cares1_23)]
pub use crate::utils::expand_name;
pub use crate::utils::expand_string;
pub use crate::utils::thread_safety;
pub use crate::utils::version;
