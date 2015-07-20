extern crate c_ares_sys;
extern crate libc;

use std::ffi::CString;
use std::mem;
use std::os::unix::io;
use std::ptr;

use a::{
    AResults,
    query_a_callback,
};
use aaaa::{
    AAAAResults,
    query_aaaa_callback,
};
use cname::{
    CNameResult,
    query_cname_callback,
};
use flags::Flags;
use types::{
    AresError,
    DnsClass,
    QueryType,
};
use utils::ares_error;

/// Used to configure the behaviour of the name resolver.
#[derive(Clone)]
pub struct Options {
    ares_options: c_ares_sys::Struct_ares_options,
    optmask: libc::c_int,
    domains: Vec<CString>,
    lookups: Option<CString>,
}

impl Options {
    /// Returns a fresh `Options`, on which no values are set.
    pub fn new() -> Options {
        Options {
            ares_options: c_ares_sys::Struct_ares_options::default(),
            optmask: 0,
            domains: Vec::new(),
            lookups: None,
        }
    }

    /// Set flags controlling the behaviour of the resolver.  The available
    /// flags are documented [here](flags/index.html).
    pub fn set_flags(&mut self, flags: Flags) -> &mut Self {
        self.ares_options.flags = flags.bits();
        self.optmask = self.optmask | c_ares_sys::ARES_OPT_FLAGS;
        self
    }

    /// Set the number of milliseconds each name server is given to respond to
    /// a query on the first try.  (After the first try, the timeout algorithm
    /// becomes more complicated, but scales linearly with the value of
    /// timeout.) The default is five seconds.
    pub fn set_timeout(&mut self, ms: u32) -> &mut Self {
        self.ares_options.timeout = ms as libc::c_int;
        self.optmask = self.optmask | c_ares_sys::ARES_OPT_TIMEOUTMS;
        self
    }

    /// Set the number of tries the resolver will try contacting each name
    /// server before giving up. The default is four tries.
    pub fn set_tries(&mut self, tries: u32) -> &mut Self {
        self.ares_options.tries = tries as libc::c_int;
        self.optmask = self.optmask | c_ares_sys::ARES_OPT_TRIES;
        self
    }

    /// Set the number of dots which must be present in a domain name for it to
    /// be queried for "as is" prior to querying for it with the default domain
    /// extensions appended. The default value is 1 unless set otherwise by
    /// resolv.conf or the RES_OPTIONS environment variable.
    pub fn set_ndots(&mut self, ndots: u32) -> &mut Self {
        self.ares_options.ndots = ndots as libc::c_int;
        self.optmask = self.optmask | c_ares_sys::ARES_OPT_NDOTS;
        self
    }

    /// Set the UDP port to use for queries. The default value is 53, the
    /// standard name service port.
    pub fn set_udp_port(&mut self, udp_port: u16) -> &mut Self {
        self.ares_options.udp_port = udp_port as libc::c_ushort;
        self.optmask = self.optmask | c_ares_sys::ARES_OPT_UDP_PORT;
        self
    }

    /// Set the TCP port to use for queries. The default value is 53, the
    /// standard name service port.
    pub fn set_tcp_port(&mut self, tcp_port: u16) -> &mut Self {
        self.ares_options.tcp_port = tcp_port as libc::c_ushort;
        self.optmask = self.optmask | c_ares_sys::ARES_OPT_TCP_PORT;
        self
    }

    /// Set the domains to search, instead of the domains specified in
    /// resolv.conf or the domain derived from the kernel hostname variable.
    pub fn set_domains(&mut self, domains: &[&str]) -> &mut Self {
        self.domains = domains
            .iter()
            .map(|&s| CString::new(s).unwrap())
            .collect();
        self.optmask = self.optmask | c_ares_sys::ARES_OPT_DOMAINS;
        self
    }

    /// Set the lookups to perform for host queries. `lookups` should be set to
    /// a string of the characters "b" or "f", where "b" indicates a DNS lookup
    /// and "f" indicates a lookup in the hosts file.
    pub fn set_lookups(&mut self, lookups: &str) -> &mut Self {
        let c_lookups = CString::new(lookups).unwrap();
        self.lookups = Some(c_lookups);
        self.optmask = self.optmask | c_ares_sys::ARES_OPT_LOOKUPS;
        self
    }

    /// Set the socket send buffer size.
    pub fn set_sock_send_buffer_size(&mut self, size: u32) -> &mut Self {
        self.ares_options.socket_send_buffer_size = size as libc::c_int;
        self.optmask = self.optmask | c_ares_sys::ARES_OPT_SOCK_SNDBUF;
        self
    }

    /// Set the socket receive buffer size.
    pub fn set_sock_receive_buffer_size(&mut self, size: u32) -> &mut Self {
        self.ares_options.socket_receive_buffer_size = size as libc::c_int;
        self.optmask = self.optmask | c_ares_sys::ARES_OPT_SOCK_RCVBUF;
        self
    }

    /// Configure round robin selection of nameservers.
    pub fn set_rotate(&mut self) -> &mut Self {
        self.optmask = self.optmask | c_ares_sys::ARES_OPT_ROTATE;
        self
    }

    /// Set the EDNS packet size.
    pub fn set_ednspsz(&mut self, size: u32) -> &mut Self {
        self.ares_options.ednspsz = size as libc::c_int;
        self.optmask = self.optmask | c_ares_sys::ARES_OPT_EDNSPSZ;
        self
    }
}

/// A channel for name service lookups.
#[derive(Debug)]
pub struct Channel {
    ares_channel: c_ares_sys::ares_channel,
}

impl Channel {
    /// Create a new channel for name service lookups, providing a callback
    /// for socket state changes.
    ///
    /// `callback(socket, read, write)` will be called when a socket changes
    /// state:
    ///
    /// -  `read` is set to true if the socket should listen for read events
    /// -  `write` is set to true if the socket should listen to write events.
    pub fn new<F>(
        callback: F,
        mut options: Options) -> Result<Channel, AresError>
        where F: FnMut(io::RawFd, bool, bool) + 'static {
        options.optmask = options.optmask | c_ares_sys::ARES_OPT_SOCK_STATE_CB;
        options.ares_options.sock_state_cb = Some(socket_callback::<F>);
        options.ares_options.sock_state_cb_data = unsafe {
            mem::transmute(Box::new(callback))
        };
        Self::create_channel(options)
    }

    fn create_channel(mut options: Options) -> Result<Channel, AresError> {
        // Initialize the library.
        let lib_rc = unsafe {
            c_ares_sys::ares_library_init(c_ares_sys::ARES_LIB_INIT_ALL)
        };
        if lib_rc != c_ares_sys::ARES_SUCCESS {
            return Err(ares_error(lib_rc))
        }

        // We deferred setting up domains in the options - do it now.
        let domains: Vec<_> = options.domains
            .iter()
            .map(|s| s.as_ptr())
            .collect();
        options.ares_options.domains =
            domains.as_ptr() as *mut *mut libc::c_char;
        options.ares_options.ndomains = domains.len() as libc::c_int;

        // Likewise for lookups.
        for c_lookup in options.lookups.iter() {
            options.ares_options.lookups =
                c_lookup.as_ptr() as *mut libc::c_char;
        }

        // Initialize the channel.
        let mut ares_channel = ptr::null_mut();
        let channel_rc = unsafe {
            c_ares_sys::ares_init_options(
                &mut ares_channel,
                &mut options.ares_options,
                options.optmask)
        };
        if channel_rc != c_ares_sys::ARES_SUCCESS {
            unsafe { c_ares_sys::ares_library_cleanup(); }
            return Err(ares_error(channel_rc))
        }

        let channel = Channel {
            ares_channel: ares_channel,
        };
        Ok(channel)
    }

    /// Handle input, output, and timeout events associated with the specified
    /// file descriptors (sockets).
    ///
    /// Providing a value for `read_fd` indicates that the identified socket
    /// is readable; likewise providing a value for `write_fd` indicates that
    /// the identified socket is writable.  Use `INVALID_FD` for "no action".
    pub fn process_fd(&mut self, read_fd: io::RawFd, write_fd: io::RawFd) {
        unsafe {
            c_ares_sys::ares_process_fd(
                self.ares_channel,
                read_fd as c_ares_sys::ares_socket_t,
                write_fd as c_ares_sys::ares_socket_t);
        }
    }

    /// Set the list of servers to contact, instead of the servers specified
    /// in resolv.conf or the local named.
    ///
    /// String format is `host[:port]`.  IPv6 addresses with ports require
    /// square brackets eg `[2001:4860:4860::8888]:53`.
    pub fn set_servers(&mut self, servers: &[&str]) -> Result<(), AresError> {
        let servers_csv = servers.connect(",");
        let c_servers = CString::new(servers_csv).unwrap();
        let ares_rc = unsafe {
            c_ares_sys::ares_set_servers_csv(
                self.ares_channel,
                c_servers.as_ptr())
        };
        if ares_rc != c_ares_sys::ARES_SUCCESS {
            Err(ares_error(ares_rc))
        } else {
            Ok(())
        }
    }

    /// Look up the A record associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_a<F>(&mut self, name: &str, handler: F)
        where F: FnOnce(Result<AResults, AresError>) + 'static {
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

    /// Look up the AAAA record associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_aaaa<F>(&mut self, name: &str, handler: F)
        where F: FnOnce(Result<AAAAResults, AresError>) + 'static {
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

    /// Look up the CNAME record associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_cname<F>(&mut self, name: &str, handler: F)
        where F: FnOnce(Result<CNameResult, AresError>) + 'static {
        let c_name = CString::new(name).unwrap();
        unsafe {
            let c_arg: *mut libc::c_void = mem::transmute(Box::new(handler));
            c_ares_sys::ares_query(
                self.ares_channel,
                c_name.as_ptr(),
                DnsClass::IN as libc::c_int,
                QueryType::CNAME as libc::c_int,
                Some(query_cname_callback::<F>),
                c_arg);
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

pub unsafe extern "C" fn socket_callback<F>(
    data: *mut libc::c_void,
    socket_fd: c_ares_sys::ares_socket_t,
    readable: libc::c_int,
    writable: libc::c_int)
    where F: FnMut(io::RawFd, bool, bool) + 'static {
    let mut handler: Box<F> = mem::transmute(data);
    handler(socket_fd as io::RawFd, readable != 0, writable != 0);
}
