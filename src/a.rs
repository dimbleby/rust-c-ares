extern crate c_ares_sys;
extern crate libc;

use std::net::Ipv4Addr;
use std::ptr;

use types::{
    AresError,
    hostent,
};
use utils::ares_error;

/// The result of a successful lookup for an A record.
#[derive(Debug, Clone)]
pub struct AResult {
    /// The IP addresses returned by the lookup.
    pub ip_addrs: Vec<Ipv4Addr>,
}

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
    unsafe {
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
        ip_addrs: answers,
    };
    Ok(result)
}
