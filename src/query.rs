use std::os::raw::{c_int, c_uchar, c_void};
use std::slice;

use crate::error::{Error, Result};
use crate::panic;

pub(crate) unsafe extern "C" fn query_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int,
) where
    F: FnOnce(Result<&[u8]>) + Send + 'static,
{
    let result = if status == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
        let data = unsafe { slice::from_raw_parts(abuf, alen as usize) };
        Ok(data)
    } else {
        Err(Error::from(status))
    };
    let handler = unsafe { Box::from_raw(arg.cast::<F>()) };
    panic::catch(|| handler(result));
}
