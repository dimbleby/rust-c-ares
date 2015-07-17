//! Low-level bindings for the c-ares library.
//!
//! In most cases this crate should not be used directly.  The c-ares crate
//! provides a safe wrapper and should be preferred wherever possible.

#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

extern crate libc;

use libc::types::os::arch::c95::size_t;
use libc::types::os::common::bsd44::{in_addr, sockaddr, socklen_t};
use libc::types::os::common::posix01::timeval;

pub type Struct_in_addr = in_addr;
pub type Struct_sockaddr = sockaddr;
pub type Struct_timeval = timeval;

include!("ffi.rs");
include!("constants.rs");
