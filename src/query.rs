extern crate c_ares_sys;

use std::os::raw::{
    c_int,
    c_uchar,
    c_void,
};
use std::slice;

use error::AresError;
use utils::ares_error;

pub unsafe extern "C" fn query_callback<F>(
    arg: *mut c_void,
    status: c_int,
    _timeouts: c_int,
    abuf: *mut c_uchar,
    alen: c_int)
    where F: FnOnce(Result<&[u8], AresError>) + 'static {
    let result = if status == c_ares_sys::ARES_SUCCESS {
        let data = slice::from_raw_parts(abuf, alen as usize);
        Ok(data)
    } else {
        Err(ares_error(status))
    };
    let handler = Box::from_raw(arg as *mut F);
    handler(result);
}
