use core::ffi::c_char;
use std::ops::Deref;
use std::str;

use crate::utils::c_string_as_str_unchecked;

/// A smart pointer wrapping a string as allocated by c-ares.
pub struct AresString {
    ares_string: *mut c_char,
}

impl AresString {
    #[allow(dead_code)]
    pub(crate) fn new(ares_string: *mut c_char) -> Self {
        AresString { ares_string }
    }
}

impl Deref for AresString {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        unsafe { c_string_as_str_unchecked(self.ares_string) }
    }
}

impl Drop for AresString {
    fn drop(&mut self) {
        unsafe { c_ares_sys::ares_free_string(self.ares_string.cast()) }
    }
}
