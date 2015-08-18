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
mod a;
mod aaaa;
mod srv;
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
mod types;
mod txt;
mod soa;
mod utils;

// Re-export public interfaces.
pub use a::AResults;
pub use aaaa::AAAAResults;
pub use channel::{
    Channel,
    GetSock,
    Options,
};
pub use cname::CNameResult;
pub use error::AresError;
pub use host::HostResults;
pub use hostent::{
    HostEntResults,
    HostAddressResult,
    HostAliasResult,
};
pub use mx::{
    MXResult,
    MXResults,
};
pub use nameinfo::NameInfoResult;
pub use naptr::{
    NAPTRResult,
    NAPTRResults,
};
pub use ns::{
    NSResult,
    NSResults,
};
pub use ptr::{
    PTRResult,
    PTRResults,
};
pub use srv::{
    SRVResult,
    SRVResults,
};
pub use types::{
    AddressFamily,
    INVALID_FD,
    IpAddr,
};
pub use txt::{
    TXTResult,
    TXTResults,
};
pub use soa::SOAResult;
