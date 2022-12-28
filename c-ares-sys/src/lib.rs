//! Low-level bindings for the c-ares library.
//!
//! In most cases this crate should not be used directly.  The c-ares crate provides a safe wrapper
//! and should be preferred wherever possible.

extern crate c_types;
extern crate libc;

#[cfg(target_os = "android")]
extern crate jni_sys;

mod constants;
mod ffi;

pub use crate::constants::*;
pub use crate::ffi::*;
