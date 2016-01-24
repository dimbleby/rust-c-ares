//! A safe wrapper for the [`c-ares`](http://c-ares.haxx.se) library.
//!
//! Usage is as follows:
//!
//! -  Create a `Channel`.
//!
//! -  Make queries on the `Channel`.  Queries all take callbacks, which will
//!    be called when the query completes.
//!
//! -  Have `c-ares` tell you what file descriptors to listen on for read and /
//!    or write events.  You can do this either by providing a callback, which
//!    is called whenever the set of interesting file descriptors changes, or
//!    by querying the `Channel` directly with `get_sock()`.
//!
//! -  Do as `c-ares` asks.  That is, listen for the events that it requests,
//!    on the file descriptors that it cares about.
//!
//! -  When a file descriptor becomes readable or writable, call `process_fd()`
//!    on the `Channel` to tell `c-ares` what has happened.
//!
//! -  If you have queries pending and don't see events happening, you still
//!    need to call `process_fd()` at some point anyway - to give `c-ares` an
//!    opportunity to process any requests that have timed out.
//!
//! Complete examples showing how to use the library can be found
//! [here](https://github.com/dimbleby/rust-c-ares/tree/master/examples).
#[macro_use] extern crate bitflags;
extern crate c_types;
extern crate ip;

mod a;
mod aaaa;
mod channel;
mod cname;
mod error;
pub mod flags;
mod host;
mod hostent;
mod mx;
mod nameinfo;
mod naptr;
pub mod ni_flags;
mod ns;
mod ptr;
mod query;
mod srv;
mod types;
mod txt;
mod soa;
mod utils;

#[cfg(test)]
mod tests;

// Re-export types from other crates that are on our interface.
pub use c_types::fd_set;
pub use ip::IpAddr;

// Re-export public interfaces.
pub use a::{
    AResult,
    AResults,
    AResultsIter,
};
pub use aaaa::{
    AAAAResult,
    AAAAResults,
    AAAAResultsIter,
};
pub use channel::{
    Channel,
    GetSock,
    GetSockIter,
    Options,
};
pub use cname::CNameResults;
pub use error::AresError;
pub use host::HostResults;
pub use hostent::{
    HostAddressResultsIter,
    HostAliasResultsIter,
};
pub use mx::{
    MXResult,
    MXResults,
    MXResultsIter,
};
pub use nameinfo::NameInfoResult;
pub use naptr::{
    NAPTRResult,
    NAPTRResults,
    NAPTRResultsIter,
};
pub use ns::NSResults;
pub use ptr::PTRResults;
pub use soa::SOAResult;
pub use srv::{
    SRVResult,
    SRVResults,
    SRVResultsIter,
};
pub use txt::{
    TXTResults,
    TXTResultsIter,
};
pub use types::{
    AddressFamily,
    Socket,
    SOCKET_BAD,
};
