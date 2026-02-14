use core::ffi::c_char;
use std::fmt;
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

unsafe impl Send for AresString {}
unsafe impl Sync for AresString {}

impl fmt::Debug for AresString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

/// A smart pointer wrapping a byte buffer as allocated by c-ares.
pub struct AresBuf {
    buf: *mut u8,
    len: usize,
}

impl AresBuf {
    #[allow(dead_code)]
    pub(crate) fn new(buf: *mut u8, len: usize) -> Self {
        AresBuf { buf, len }
    }
}

impl Deref for AresBuf {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.buf, self.len) }
    }
}

impl Drop for AresBuf {
    fn drop(&mut self) {
        unsafe { c_ares_sys::ares_free_string(self.buf.cast()) }
    }
}

unsafe impl Send for AresBuf {}
unsafe impl Sync for AresBuf {}

impl fmt::Debug for AresBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&**self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ares_string_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<AresString>();
    }

    #[test]
    fn ares_string_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<AresString>();
    }

    #[test]
    fn ares_buf_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<AresBuf>();
    }

    #[test]
    fn ares_buf_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<AresBuf>();
    }

    #[test]
    fn ares_string_debug() {
        fn assert_debug<T: fmt::Debug>() {}
        assert_debug::<AresString>();
    }

    #[test]
    fn ares_buf_debug() {
        fn assert_debug<T: fmt::Debug>() {}
        assert_debug::<AresBuf>();
    }
}
