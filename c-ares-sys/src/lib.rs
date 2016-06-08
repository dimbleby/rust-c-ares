//! Low-level bindings for the c-ares library.
//!
//! In most cases this crate should not be used directly.  The c-ares crate
//! provides a safe wrapper and should be preferred wherever possible.

extern crate libc;
extern crate c_types;

#[cfg(windows)]
extern crate winapi;

mod ffi;
mod constants;

pub use constants::*;
pub use ffi::*;
