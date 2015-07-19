//! A safe wrapper for the [`c-ares`](http://c-ares.haxx.se) library.
//!
//! Usage is as follows:
//!
//! -  Create a `Channel`, providing a callback which will be used to notify
//!    you when `c-ares` wants you to listen for read or write events on its
//!    behalf.
//!
//! -  When this callback is invoked, do what it asks!
//!
//! -  When a file descriptor becomes readable or writable, call `process_fd()`
//!    on the channel to tell `c-ares` what has happened.
//!
//! -  `c-ares` doesn't create any threads of its own.  So if you have queries
//!    pending and don't see events happening, you still need to call
//!    `process_fd()` at some point anyway - to give `c-ares` an opportunity to
//!    process any requests that have timed out.
//!
//! -  Make queries on the channel.  Queries all take callbacks, which will be
//!    called when the query completes.
//!
//! This model is a good fit for an event loop - as provided by
//! [`mio`](https://github.com/carllerche/mio), for example.
//!
//! Complete examples showing how to use the library can be found
//! [here](https://github.com/dimbleby/rust-c-ares/tree/master/examples).
#[macro_use] extern crate bitflags;
mod callbacks;
mod channel;
pub mod flags;
mod parsers;
mod types;
mod utils;

// Re-export public interfaces.
pub use channel::{
    Channel,
    Options
};
pub use parsers::{
    parse_a_result,
    parse_aaaa_result,
    parse_srv_result,
    parse_cname_result,
};
pub use types::{
    AresError,
    AResult,
    AAAAResult,
    SRVResult,
    CNameResult,
    INVALID_FD,
};
pub use utils::str_error;
