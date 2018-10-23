//! A safe wrapper for the [`c-ares`](https://c-ares.haxx.se) library.
//!
//! This crate is a fairly faithful wrapper of `c-ares`; which is to say that it preserves some of
//! the complication of using the underlying library:
//!
//! - Direct usage of this crate requires you to pay attention to `c-ares` as it tells you which
//! file descriptors it cares about, and to poll for activity on those file descriptors.
//!
//! - This likely requires you to have an event loop or similar with which to integrate.
//!
//! If that sounds a bit too much like hard work, you should probably prefer the
//! [`c-ares-resolver`](https://crates.io/crates/c-ares-resolver) crate, which takes care of all
//! that stuff for you and presents a much simpler API.
//!
//! Still here?  Usage of this crate is as follows:
//!
//! - Create a `Channel`.
//!
//! - Make queries on the `Channel`.  Queries all take callbacks, which will be called when the
//! query completes.
//!
//! - Have `c-ares` tell you what file descriptors to listen on for read and / or write events.
//! You can do this either by providing a callback, which is called whenever the set of interesting
//! file descriptors changes, or by querying the `Channel` directly either with `get_sock()` or
//! with `fds()`.
//!
//! - Do as `c-ares` asks.  That is, listen for the events that it requests, on the file
//! descriptors that it cares about.
//!
//! - When a file descriptor becomes readable or writable, call either `process_fd()` or
//! `process()` on the `Channel` to tell `c-ares` what has happened.
//!
//! - If you have queries pending and don't see events happening, you still need to call either
//! `process_fd()` or `process()` at some point anyway - to give `c-ares` an opportunity to process
//! any requests that have timed out.
//!
//! Complete examples showing how to use the library can be found
//! [here](https://github.com/dimbleby/rust-c-ares/tree/master/examples).
#![deny(missing_docs)]
#[macro_use]
extern crate bitflags;
extern crate c_ares_sys;
extern crate c_types;
extern crate itertools;

#[macro_use]
mod macros;
mod a;
mod aaaa;
mod channel;
mod cname;
mod error;
mod flags;
mod host;
mod hostent;
mod mx;
mod nameinfo;
mod naptr;
mod ni_flags;
mod ns;
mod panic;
mod ptr;
mod query;
mod soa;
mod srv;
mod txt;
mod types;
mod utils;

#[cfg(test)]
mod tests;

// Re-export public interfaces.
pub use a::{AResult, AResults, AResultsIter};
pub use aaaa::{AAAAResult, AAAAResults, AAAAResultsIter};
pub use channel::{Channel, GetSock, GetSockIter, Options};
pub use cname::CNameResults;
pub use error::{Error, Result};
pub use flags::Flags;
pub use host::HostResults;
pub use hostent::{HostAddressResultsIter, HostAliasResultsIter};
pub use mx::{MXResult, MXResults, MXResultsIter};
pub use nameinfo::NameInfoResult;
pub use naptr::{NAPTRResult, NAPTRResults, NAPTRResultsIter};
pub use ni_flags::NIFlags;
pub use ns::NSResults;
pub use ptr::PTRResults;
pub use soa::SOAResult;
pub use srv::{SRVResult, SRVResults, SRVResultsIter};
pub use txt::{TXTResult, TXTResults, TXTResultsIter};
pub use types::{AddressFamily, Socket, SOCKET_BAD};
pub use utils::version;
