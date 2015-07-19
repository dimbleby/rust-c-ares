//! Low-level bindings for the c-ares library.
//!
//! In most cases this crate should not be used directly.  The c-ares crate
//! provides a safe wrapper and should be preferred wherever possible.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
extern crate libc;

mod ffi;
mod constants;

pub use constants::*;
pub use ffi::*;
