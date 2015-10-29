extern crate c_ares_sys;
extern crate libc;

use std::slice;

use error::AresError;
use utils::ares_error;

pub unsafe extern "C" fn query_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<&[u8], AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        Ok(data)
    };
    let handler = Box::from_raw(arg as *mut F);
    handler(result);
}
