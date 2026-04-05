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

impl fmt::Display for AresString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&**self, f)
    }
}

impl AsRef<str> for AresString {
    fn as_ref(&self) -> &str {
        self
    }
}

impl From<AresString> for String {
    fn from(s: AresString) -> Self {
        (*s).to_owned()
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

impl AsRef<[u8]> for AresBuf {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl From<AresBuf> for Vec<u8> {
    fn from(b: AresBuf) -> Self {
        (*b).to_vec()
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
    fn ares_string_debug_output() {
        let name = crate::expand_name(b"\x07example\x03com\x00", 0)
            .expect("expand_name")
            .0;
        let debug = format!("{name:?}");
        assert!(debug.contains("example.com"));
    }

    #[test]
    fn ares_buf_debug() {
        fn assert_debug<T: fmt::Debug>() {}
        assert_debug::<AresBuf>();
    }

    #[test]
    fn ares_buf_debug_output() {
        let data = crate::expand_string(b"\x05hello", 0)
            .expect("expand_string")
            .0;
        let debug = format!("{data:?}");
        assert!(!debug.is_empty());
    }

    #[test]
    fn ares_string_display() {
        let name = crate::expand_name(b"\x07example\x03com\x00", 0)
            .expect("expand_name")
            .0;
        assert_eq!(format!("{name}"), "example.com");
    }

    #[test]
    fn ares_string_as_ref_str() {
        let name = crate::expand_name(b"\x07example\x03com\x00", 0)
            .expect("expand_name")
            .0;
        let s: &str = name.as_ref();
        assert_eq!(s, "example.com");
    }

    #[test]
    fn ares_buf_as_ref_slice() {
        let data = crate::expand_string(b"\x05hello", 0)
            .expect("expand_string")
            .0;
        let bytes: &[u8] = data.as_ref();
        assert_eq!(bytes, b"hello");
    }

    #[test]
    fn ares_string_into_string() {
        let name = crate::expand_name(b"\x07example\x03com\x00", 0)
            .expect("expand_name")
            .0;
        let owned: String = name.into();
        assert_eq!(owned, "example.com");
    }

    #[test]
    fn ares_buf_into_vec() {
        let data = crate::expand_string(b"\x05hello", 0)
            .expect("expand_string")
            .0;
        let owned: Vec<u8> = data.into();
        assert_eq!(owned, b"hello");
    }
}
