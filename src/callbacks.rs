extern crate c_ares_sys;
extern crate libc;

use std::mem;
use std::os::unix::io;
use std::slice;

use cname::{
    CNameResult,
    parse_cname_result,
};
use parsers::{
    parse_a_result,
    parse_aaaa_result,
};
use types::{
    AresError,
    AResult,
    AAAAResult,
};
use utils::ares_error;

pub unsafe extern "C" fn socket_callback<F>(
    data: *mut libc::c_void,
    socket_fd: c_ares_sys::ares_socket_t,
    readable: libc::c_int,
    writable: libc::c_int)
    where F: FnMut(io::RawFd, bool, bool) + 'static {
    let mut handler: Box<F> = mem::transmute(data);
    handler(socket_fd as io::RawFd, readable != 0, writable != 0);
}

pub unsafe extern "C" fn query_a_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<AResult, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        parse_a_result(data)
    };
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}

pub unsafe extern "C" fn query_aaaa_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<AAAAResult, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        parse_aaaa_result(data)
    };
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}

pub unsafe extern "C" fn query_cname_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<CNameResult, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let data = slice::from_raw_parts(abuf, alen as usize);
        parse_cname_result(data)
    };
    let handler: Box<F> = mem::transmute(arg);
    handler(result);
}
