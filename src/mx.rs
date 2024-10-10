use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{c_int, c_uchar, c_void};
use std::ptr;
use std::slice;

use itertools::Itertools;

use crate::error::{Error, Result};
use crate::panic;
use crate::utils::hostname_as_str;

/// The result of a successful MX lookup.
#[derive(Debug)]
pub struct MXResults {
    mx_reply: *mut c_ares_sys::ares_mx_reply,
    phantom: PhantomData<c_ares_sys::ares_mx_reply>,
}

/// The contents of a single MX record.
#[derive(Clone, Copy)]
pub struct MXResult<'a> {
    mx_reply: &'a c_ares_sys::ares_mx_reply,
}

impl MXResults {
    /// Obtain an `MXResults` from the response to an MX lookup.
    pub fn parse_from(data: &[u8]) -> Result<MXResults> {
        let mut mx_reply: *mut c_ares_sys::ares_mx_reply = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_mx_reply(data.as_ptr(), data.len() as c_int, &mut mx_reply)
        };
        if parse_status == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            let result = MXResults::new(mx_reply);
            Ok(result)
        } else {
            Err(Error::from(parse_status))
        }
    }

    fn new(mx_reply: *mut c_ares_sys::ares_mx_reply) -> Self {
        MXResults {
            mx_reply,
            phantom: PhantomData,
        }
    }

    /// Returns an iterator over the `MXResult` values in this `MXResults`.
    pub fn iter(&self) -> MXResultsIter {
        MXResultsIter {
            next: unsafe { self.mx_reply.as_ref() },
        }
    }
}

impl fmt::Display for MXResults {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        let results = self.iter().format("}, {");
        write!(fmt, "[{{{results}}}]")
    }
}

/// Iterator of `MXResult`s.
#[derive(Clone, Copy)]
pub struct MXResultsIter<'a> {
    next: Option<&'a c_ares_sys::ares_mx_reply>,
}

impl<'a> Iterator for MXResultsIter<'a> {
    type Item = MXResult<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        let opt_reply = self.next;
        self.next = opt_reply.and_then(|reply| unsafe { reply.next.as_ref() });
        opt_reply.map(|reply| MXResult { mx_reply: reply })
    }
}

impl<'a> IntoIterator for &'a MXResults {
    type Item = MXResult<'a>;
    type IntoIter = MXResultsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Drop for MXResults {
    fn drop(&mut self) {
        unsafe { c_ares_sys::ares_free_data(self.mx_reply.cast()) }
    }
}

unsafe impl Send for MXResults {}
unsafe impl Sync for MXResults {}
unsafe impl Send for MXResult<'_> {}
unsafe impl Sync for MXResult<'_> {}
unsafe impl Send for MXResultsIter<'_> {}
unsafe impl Sync for MXResultsIter<'_> {}

impl<'a> MXResult<'a> {
    /// Returns the hostname in this `MXResult`.
    pub fn host(self) -> &'a str {
        unsafe { hostname_as_str(self.mx_reply.host) }
    }

    /// Returns the priority from this `MXResult`.
    pub fn priority(self) -> u16 {
        self.mx_reply.priority
    }
}

impl fmt::Display for MXResult<'_> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "Hostname: {}, ", self.host())?;
        write!(fmt, "Priority: {}", self.priority())
    }
}

pub(crate) unsafe extern "C" fn query_mx_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<MXResults>) + Send + 'static,
{
    ares_callback!(arg.cast::<F>(), status, abuf, alen, MXResults::parse_from);
}
