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
mod a;
mod aaaa;
mod srv;
mod channel;
mod cname;
pub mod flags;
mod types;
mod utils;

// Re-export public interfaces.
pub use a::{
    AResult,
};
pub use aaaa::{
    AAAAResult,
};
pub use srv::{
    SRVResult,
};
pub use channel::{
    Channel,
    Options
};
pub use cname::{
    CNameResult,
};
pub use types::{
    AresError,
    INVALID_FD,
};
pub use utils::str_error;
