extern crate c_ares_sys;
extern crate libc;

use std::ffi::{CStr, CString};
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::unix::io;
use std::ptr;

#[derive(Debug)]
pub enum AresError {
    ENODATA = 1,
    EFORMERR,
    ESERVFAIL,
    ENOTFOUND,
    ENOTIMP,
    EREFUSED,
    EBADQUERY,
    EBADNAME,
    EBADFAMILY,
    EBADRESP,
    ECONNREFUSED,
    ETIMEOUT,
    EOF,
    EFILE,
    ENOMEM,
    EDESTRUCTION,
    EBADSTR,
    EBADFLAGS,
    ENONAME,
    EBADHINTS,
    ENOTINITIALIZED,
    ELOADIPHLPAPI,
    EADDRGETNETWORKPARAMS,
    ECANCELLED,
    UNKNOWN,
}

pub const SOCKET_BAD: io::RawFd = c_ares_sys::ARES_SOCKET_BAD;

pub struct AResult {
    pub ip_addrs: Vec<Ipv4Addr>,
}

pub struct AAAAResult {
    pub ip_addrs: Vec<Ipv6Addr>,
}

pub struct Channel {
    ares_channel: c_ares_sys::ares_channel,
}

impl Channel {
    pub fn new<F>(callback: F) -> Result<Channel, AresError> 
        where F: FnOnce(io::RawFd, bool, bool) + 'static {
        let lib_rc = unsafe {
            c_ares_sys::ares_library_init(c_ares_sys::ARES_LIB_INIT_ALL)
        };
        match lib_rc {
            c_ares_sys::ARES_SUCCESS => (),
            _ => return Err(ares_error(lib_rc))
        }

        // TODO suport user-provided options
        let mut ares_channel = ptr::null_mut();
        let mut options = c_ares_sys::Struct_ares_options::default();
        options.flags = c_ares_sys::ARES_FLAG_STAYOPEN;
        options.timeout = 500;
        options.tries = 3;
        options.sock_state_cb = Some(socket_callback::<F>);
        options.sock_state_cb_data = unsafe { mem::transmute(Box::new(callback)) };
        let optmask =
            c_ares_sys::ARES_OPT_FLAGS | 
            c_ares_sys::ARES_OPT_TIMEOUT | 
            c_ares_sys::ARES_OPT_TRIES |
            c_ares_sys::ARES_OPT_SOCK_STATE_CB;
        let channel_rc = unsafe {
            c_ares_sys::ares_init_options(&mut ares_channel, &mut options, optmask)
        };

        match channel_rc {
            c_ares_sys::ARES_SUCCESS => (),
            _ => {
                unsafe { c_ares_sys::ares_library_cleanup(); }
                return Err(ares_error(channel_rc))
            }
        }
        let channel = Channel {
            ares_channel: ares_channel,
        };

        // TODO ares_set_servers() here too?
        Ok(channel)
    }

    pub fn query_a<F>(&mut self, name: &str, handler: F)
        where F: FnOnce(Result<AResult, AresError>) + 'static {
        let c_name = CString::new(name).unwrap();
        unsafe {
            let c_arg: *mut libc::c_void = mem::transmute(Box::new(handler));
            c_ares_sys::ares_query(
                self.ares_channel,
                c_name.as_ptr(),
                DnsClass::IN as libc::c_int,
                QueryType::A as libc::c_int,
                Some(query_a_callback::<F>),
                c_arg);
        }
    }

    pub fn query_aaaa<F>(&mut self, name: &str, handler: F)
        where F: FnOnce(Result<AAAAResult, AresError>) + 'static {
        let c_name = CString::new(name).unwrap();
        unsafe {
            let c_arg: *mut libc::c_void = mem::transmute(Box::new(handler));
            c_ares_sys::ares_query(
                self.ares_channel,
                c_name.as_ptr(),
                DnsClass::IN as libc::c_int,
                QueryType::AAAA as libc::c_int,
                Some(query_aaaa_callback::<F>),
                c_arg);
        }
    }

    pub fn process_fd(&mut self, read_fd: io::RawFd, write_fd: io::RawFd) {
        unsafe { c_ares_sys::ares_process_fd(self.ares_channel, read_fd, write_fd); }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        unsafe {
            c_ares_sys::ares_destroy(self.ares_channel);
            c_ares_sys::ares_library_cleanup();
        }
    }
}

unsafe impl Send for Channel { }

pub fn str_error<'a>(code: AresError) -> &'a str {
    let buf = unsafe {
        let ptr = c_ares_sys::ares_strerror(code as libc::c_int);
        CStr::from_ptr(ptr).to_bytes()
    };
    std::str::from_utf8(buf).unwrap()
}

// Convert an error code from the library into a more strongly typed AresError.
fn ares_error(code: libc::c_int) -> AresError {
    match code {
        c_ares_sys::ARES_ENODATA => AresError::ENODATA,
        c_ares_sys::ARES_EFORMERR => AresError::EFORMERR,
        c_ares_sys::ARES_ESERVFAIL => AresError::ESERVFAIL,
        c_ares_sys::ARES_ENOTFOUND => AresError::ENOTFOUND,
        c_ares_sys::ARES_ENOTIMP => AresError::ENOTIMP,
        c_ares_sys::ARES_EREFUSED => AresError::EREFUSED,
        c_ares_sys::ARES_EBADQUERY => AresError::EBADQUERY,
        c_ares_sys::ARES_EBADNAME => AresError::EBADNAME,
        c_ares_sys::ARES_EBADFAMILY => AresError::EBADFAMILY,
        c_ares_sys::ARES_EBADRESP => AresError::EBADRESP,
        c_ares_sys::ARES_ECONNREFUSED => AresError::ECONNREFUSED,
        c_ares_sys::ARES_ETIMEOUT => AresError::ETIMEOUT,
        c_ares_sys::ARES_EOF => AresError::EOF,
        c_ares_sys::ARES_EFILE => AresError::EFILE,
        c_ares_sys::ARES_ENOMEM => AresError::ENOMEM,
        c_ares_sys::ARES_EDESTRUCTION => AresError::EDESTRUCTION,
        c_ares_sys::ARES_EBADSTR => AresError::EBADSTR,
        c_ares_sys::ARES_EBADFLAGS => AresError::EBADFLAGS,
        c_ares_sys::ARES_ENONAME => AresError::ENONAME,
        c_ares_sys::ARES_EBADHINTS => AresError::EBADHINTS,
        c_ares_sys::ARES_ENOTINITIALIZED => AresError::ENOTINITIALIZED,
        c_ares_sys::ARES_ELOADIPHLPAPI => AresError::ELOADIPHLPAPI,
        c_ares_sys::ARES_EADDRGETNETWORKPARAMS => AresError::EADDRGETNETWORKPARAMS,
        c_ares_sys::ARES_ECANCELLED => AresError::ECANCELLED,
        _ => AresError::UNKNOWN,
    }
}

#[repr(C)]
struct hostent {
    h_name: *mut libc::c_char,
    h_aliases: *mut *mut libc::c_char,
    h_addrtype: libc::c_int,
    h_length: libc::c_int,
    h_addr_list: *mut *mut libc::c_char,
}

// See arpa/nameser.h
enum QueryType {
    A = 1,
    AAAA = 28,
}

// See arpa/nameser.h
enum DnsClass {
   IN = 1,
}

extern "C" fn socket_callback<F>(
    data: *mut libc::c_void,
    socket_fd: c_ares_sys::ares_socket_t,
    readable: libc::c_int,
    writable: libc::c_int)
    where F: FnOnce(io::RawFd, bool, bool) + 'static {
    let handler: Box<F> = unsafe { mem::transmute(data) };
    handler(socket_fd as io::RawFd, readable != 0, writable != 0);
}

extern "C" fn query_a_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<AResult, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let mut hostent: *mut hostent = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_a_reply(
                abuf,
                alen,
                &mut hostent as *mut *mut _ as *mut *mut c_ares_sys::Struct_hostent,
                ptr::null_mut(),
                ptr::null_mut())
        };
        if parse_status != c_ares_sys::ARES_SUCCESS {
            Err(ares_error(parse_status))
        } else {
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
                c_ares_sys::ares_free_hostent(
                    hostent as *mut c_ares_sys::Struct_hostent);
            }
            let result = AResult {
                ip_addrs: answers,
            };
            Ok(result)
        }
    };

    let handler: Box<F> = unsafe { mem::transmute(arg) };
    handler(result);
}

extern "C" fn query_aaaa_callback<F>(
    arg: *mut libc::c_void,
    status: libc::c_int,
    _timeouts: libc::c_int,
    abuf: *mut libc::c_uchar,
    alen: libc::c_int)
    where F: FnOnce(Result<AAAAResult, AresError>) + 'static {
    let result = if status != c_ares_sys::ARES_SUCCESS {
        Err(ares_error(status))
    } else {
        let mut hostent: *mut hostent = ptr::null_mut();
        let parse_status = unsafe {
            c_ares_sys::ares_parse_aaaa_reply(
                abuf,
                alen,
                &mut hostent as *mut *mut _ as *mut *mut c_ares_sys::Struct_hostent,
                ptr::null_mut(),
                ptr::null_mut())
        };
        if parse_status != c_ares_sys::ARES_SUCCESS {
            Err(ares_error(parse_status))
        } else {
            let mut answers = Vec::new();
            unsafe {
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
                c_ares_sys::ares_free_hostent(
                    hostent as *mut c_ares_sys::Struct_hostent);
            }
            let result = AAAAResult {
                ip_addrs: answers,
            };
            Ok(result)
        }
    };

    let handler: Box<F> = unsafe { mem::transmute(arg) };
    handler(result);
}
