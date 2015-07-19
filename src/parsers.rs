extern crate c_ares_sys;
extern crate libc;

use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;
use std::str;

use types::{
    AresError,
    AResult,
    AAAAResult,
    CNameResult,
    hostent,
};
use utils::ares_error;

/// Parse the response to an A lookup.
///
/// Users typically won't need to call this function - it's an internal utility
/// that is made public just in case someone finds a use for it.
pub fn parse_a_result(data: &[u8]) -> Result<AResult, AresError> {
    let mut hostent: *mut hostent = ptr::null_mut();
    let parse_status = unsafe {
        c_ares_sys::ares_parse_a_reply(
            data.as_ptr(),
            data.len() as libc::c_int,
            &mut hostent as *mut *mut _ as *mut *mut c_ares_sys::Struct_hostent,
            ptr::null_mut(),
            ptr::null_mut())
    };
    if parse_status != c_ares_sys::ARES_SUCCESS {
        return Err(ares_error(parse_status))
    }

    let mut answers = Vec::new();
    let mut h_name;
    unsafe {
        let c_str: &CStr = CStr::from_ptr((*hostent).h_name);
        h_name = str::from_utf8(c_str.to_bytes()).unwrap().to_owned();

        let mut ptr = (*hostent).h_addr_list;
        while !(*ptr).is_null() {
            let h_addr = *ptr;
            let ip_addr = Ipv4Addr::new(
                *h_addr as u8,
                *h_addr.offset(1) as u8,
                *h_addr.offset(2) as u8,
                *h_addr.offset(3) as u8);
            answers.push(ip_addr);
            ptr = ptr.offset(1);
        }
        c_ares_sys::ares_free_hostent(hostent as *mut c_ares_sys::Struct_hostent);
    }
    let result = AResult {
        domain: h_name,
        ip_addrs: answers,
    };
    Ok(result)
}

/// Parse the response to an AAAA lookup.
///
/// Users typically won't need to call this function - it's an internal utility
/// that is made public just in case someone finds a use for it.
pub fn parse_aaaa_result(data: &[u8]) -> Result<AAAAResult, AresError> {
    let mut hostent: *mut hostent = ptr::null_mut();
    let parse_status = unsafe {
        c_ares_sys::ares_parse_aaaa_reply(
            data.as_ptr(),
            data.len() as libc::c_int,
            &mut hostent as *mut *mut _ as *mut *mut c_ares_sys::Struct_hostent,
            ptr::null_mut(),
            ptr::null_mut())
    };
    if parse_status != c_ares_sys::ARES_SUCCESS {
        return Err(ares_error(parse_status))
    }

    let mut answers = Vec::new();
    let mut h_name;
    unsafe {
        let c_str: &CStr = CStr::from_ptr((*hostent).h_name);
        h_name = str::from_utf8(c_str.to_bytes()).unwrap().to_owned();

        let mut ptr = (*hostent).h_addr_list;
        while !(*ptr).is_null() {
            let h_addr = *ptr;
            let ip_addr = Ipv6Addr::new(
                ((*h_addr as u16) << 8) + *h_addr.offset(1) as u16,
                ((*h_addr.offset(2) as u16) << 8) + *h_addr.offset(3) as u16,
                ((*h_addr.offset(4) as u16) << 8) + *h_addr.offset(5) as u16,
                ((*h_addr.offset(6) as u16) << 8) + *h_addr.offset(7) as u16,
                ((*h_addr.offset(8) as u16) << 8) + *h_addr.offset(9) as u16,
                ((*h_addr.offset(10) as u16) << 8) + *h_addr.offset(11) as u16,
                ((*h_addr.offset(12) as u16) << 8) + *h_addr.offset(13) as u16,
                ((*h_addr.offset(14) as u16) << 8) + *h_addr.offset(15) as u16);
            answers.push(ip_addr);
            ptr = ptr.offset(1);
        }
        c_ares_sys::ares_free_hostent(hostent as *mut c_ares_sys::Struct_hostent);
    }
    let result = AAAAResult {
        domain: h_name,
        ip_addrs: answers,
    };
    Ok(result)
}

/// Parse the response to a CNAME lookup.
///
/// Users typically won't need to call this function - it's an internal utility
/// that is made public just in case someone finds a use for it.
pub fn parse_cname_result(data: &[u8]) -> Result<CNameResult, AresError> {
    let mut hostent: *mut hostent = ptr::null_mut();
    let parse_status = unsafe {
        c_ares_sys::ares_parse_a_reply(
            data.as_ptr(),
            data.len() as libc::c_int,
            &mut hostent as *mut *mut _ as *mut *mut c_ares_sys::Struct_hostent,
            ptr::null_mut(),
            ptr::null_mut())
    };
    if parse_status != c_ares_sys::ARES_SUCCESS {
        return Err(ares_error(parse_status))
    }

    let hostname = unsafe {
        let slice = CStr::from_ptr((*hostent).h_name);
        let hostname = str::from_utf8(slice.to_bytes()).unwrap().to_owned();
        c_ares_sys::ares_free_hostent(hostent as *mut c_ares_sys::Struct_hostent);
        hostname
    };
    let result = CNameResult {
        cname: hostname,
    };
    Ok(result)
}
