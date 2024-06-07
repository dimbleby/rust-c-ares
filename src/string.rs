use std::ops::Deref;
use std::os::raw::c_char;
use std::str;

use crate::utils::c_string_as_str_unchecked;

/// A smart pointer wrapping a string as allocated by c-ares.
pub struct AresString {
    ares_string: *mut c_char,
    rust_str: &'static str,
}

impl AresString {
    #[allow(dead_code)]
    pub(crate) fn new(ares_string: *mut c_char) -> Self {
        let rust_str = unsafe { c_string_as_str_unchecked(ares_string) };
        AresString {
            ares_string,
            rust_str,
        }
    }
}

impl Deref for AresString {
    type Target = str;
    fn deref(&self) -> &Self::Target {
        self.rust_str
    }
}

impl Drop for AresString {
    fn drop(&mut self) {
        unsafe { c_ares_sys::ares_free_string(self.ares_string.cast()) }
    }
}
