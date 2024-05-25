use std::ffi::CStr;
use std::ops::Deref;
use std::os::raw::c_char;

/// A smart pointer wrapping a string as allocated by c-ares.
pub struct AresString {
    ares_string: *mut c_char,
    rust_str: &'static str,
}

impl AresString {
    #[allow(dead_code)]
    pub(crate) fn new(ares_string: *mut c_char) -> Self {
        let c_str = unsafe { CStr::from_ptr(ares_string) };
        let rust_str = c_str.to_str().unwrap();
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
