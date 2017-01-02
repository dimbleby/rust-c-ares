use std::ffi::CStr;
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{
    c_int,
    c_uchar,
    c_void,
};
use std::ptr;
use std::slice;
use std::str;

use c_ares_sys;
use itertools::Itertools;

use error::{
    Error,
    Result,
};

/// The result of a successful TXT lookup.
#[derive(Debug)]
pub struct TXTResults {
    txt_reply: *mut c_ares_sys::ares_txt_ext,
    phantom: PhantomData<c_ares_sys::ares_txt_ext>,
}

/// The contents of a single TXT record.
#[derive(Clone, Copy)]
pub struct TXTResult<'a> {
    txt_reply: &'a c_ares_sys::ares_txt_ext,
}

impl TXTResults {
    /// Obtain a `TXTResults` from the response to a TXT lookup.
    pub fn parse_from(data: &[u8]) -> Result<TXTResults> {
        let mut txt_reply: *mut c_ares_sys::ares_txt_ext =
            ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_txt_reply_ext(
                data.as_ptr(),
                data.len() as c_int,
                &mut txt_reply)
        };
        if parse_status == c_ares_sys::ARES_SUCCESS {
            let result = TXTResults::new(txt_reply);
            Ok(result)
        } else {
            Err(Error::from(parse_status))
        }
    }

    fn new(txt_reply: *mut c_ares_sys::ares_txt_ext) -> TXTResults {
        TXTResults {
            txt_reply: txt_reply,
            phantom: PhantomData,
        }
    }

    /// Returns an iterator over the `TXTResult` values in this `TXTResults`.
    pub fn iter(&self) -> TXTResultsIter {
        TXTResultsIter {
            next: unsafe { self.txt_reply.as_ref() },
        }
    }
}

impl fmt::Display for TXTResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let results = self.iter().format("}, {");
        write!(fmt, "[{{{}}}]", results)?;
        Ok(())
    }
}

/// Iterator of `TXTResult`s.
#[derive(Clone, Copy)]
pub struct TXTResultsIter<'a> {
    next: Option<&'a c_ares_sys::ares_txt_ext>,
}

impl<'a> Iterator for TXTResultsIter<'a> {
    type Item = TXTResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let opt_reply = self.next;
        self.next = opt_reply.and_then(|reply| unsafe { reply.next.as_ref() });
        opt_reply.map(|reply| {
            TXTResult {
                txt_reply: reply,
            }
        })
    }
}
impl<'a> IntoIterator for &'a TXTResults {
    type Item = TXTResult<'a>;
    type IntoIter = TXTResultsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Drop for TXTResults {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_free_data(self.txt_reply as *mut c_void);
        }
    }
}

unsafe impl<'a> Send for TXTResult<'a> { }
unsafe impl<'a> Sync for TXTResult<'a> { }
unsafe impl Send for TXTResults { }
unsafe impl Sync for TXTResults { }
unsafe impl<'a> Send for TXTResultsIter<'a> { }
unsafe impl<'a> Sync for TXTResultsIter<'a> { }

impl<'a> TXTResult<'a> {
    /// Is this the start of a text record, or the continuation of a previous
    /// record?
    pub fn record_start(&self) -> bool {
        self.txt_reply.record_start != 0
    }

    /// Returns the text in this `TXTResult`.
    pub fn text(&self) -> &str {
        unsafe {
            let c_str = CStr::from_ptr(self.txt_reply.txt as *const i8);
            str::from_utf8_unchecked(c_str.to_bytes())
        }
    }
}

impl<'a> fmt::Display for TXTResult<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(
            fmt,
            "Record start: {}, Text: {}",
            self.record_start(),
            self.text()
        )?;
        Ok(())
    }
}

pub unsafe extern "C" fn query_txt_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int)
    where F: FnOnce(Result<TXTResults>) + Send + 'static {
    let result = if status == c_ares_sys::ARES_SUCCESS {
        let data = slice::from_raw_parts(abuf, alen as usize);
        TXTResults::parse_from(data)
    } else {
        Err(Error::from(status))
    };
    let handler = Box::from_raw(arg as *mut F);
    handler(result);
}
