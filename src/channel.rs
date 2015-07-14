extern crate c_ares_sys;
extern crate libc;

use std::ffi::CString;
use std::mem;
use std::os::unix::io;
use std::ptr;

use callbacks::{
    socket_callback,
    query_a_callback,
    query_aaaa_callback,
};
use types::{
    AresError,
    AResult,
    AAAAResult,
    DnsClass,
    QueryType,
};
use utils::ares_error;

pub struct Channel {
    ares_channel: c_ares_sys::ares_channel,
}

impl Channel {
    pub fn new<F>(callback: F) -> Result<Channel, AresError> 
        where F: FnOnce(io::RawFd, bool, bool) + 'static {
        let lib_rc = unsafe {
            c_ares_sys::ares_library_init(c_ares_sys::ARES_LIB_INIT_ALL)
        };
        if lib_rc != c_ares_sys::ARES_SUCCESS {
            return Err(ares_error(lib_rc))
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
        if channel_rc != c_ares_sys::ARES_SUCCESS {
            unsafe { c_ares_sys::ares_library_cleanup(); }
            return Err(ares_error(channel_rc))
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
        unsafe {
            c_ares_sys::ares_process_fd(
                self.ares_channel,
                read_fd as c_ares_sys::ares_socket_t,
                write_fd as c_ares_sys::ares_socket_t);
        }
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
