use std::ffi::CString;
use std::marker::PhantomData;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::raw::{c_int, c_void};
use std::ptr;
use std::sync::Arc;

use crate::a::{query_a_callback, AResults};
use crate::aaaa::{query_aaaa_callback, AAAAResults};
#[cfg(cares117)]
use crate::caa::{query_caa_callback, CAAResults};
use crate::cname::{query_cname_callback, CNameResults};
use crate::error::{Error, Result};
use crate::host::{get_host_callback, HostResults};
use crate::mx::{query_mx_callback, MXResults};
use crate::nameinfo::{get_name_info_callback, NameInfoResult};
use crate::naptr::{query_naptr_callback, NAPTRResults};
use crate::ni_flags::NIFlags;
use crate::ns::{query_ns_callback, NSResults};
use crate::panic;
use crate::ptr::{query_ptr_callback, PTRResults};
use crate::query::query_callback;
use crate::soa::{query_soa_callback, SOAResult};
use crate::srv::{query_srv_callback, SRVResults};
use crate::txt::{query_txt_callback, TXTResults};
use crate::types::{AddressFamily, DnsClass, QueryType, Socket};
use crate::uri::{query_uri_callback, URIResults};
use crate::utils::{
    ipv4_as_in_addr, ipv6_as_in6_addr, socket_addrv4_as_sockaddr_in, socket_addrv6_as_sockaddr_in6,
};
use crate::Flags;
use std::sync::Mutex;

// ares_library_init is not thread-safe, so we put a lock around it.
static ARES_LIBRARY_LOCK: Mutex<()> = Mutex::new(());

type SocketStateCallback = dyn FnMut(Socket, bool, bool) + Send + 'static;

/// Used to configure the behaviour of the name resolver.
pub struct Options {
    ares_options: c_ares_sys::ares_options,
    optmask: c_int,
    domains: Vec<CString>,
    lookups: Option<CString>,
    #[cfg(cares115)]
    resolvconf_path: Option<CString>,
    #[cfg(cares119)]
    hosts_path: Option<CString>,
    socket_state_callback: Option<Arc<SocketStateCallback>>,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            ares_options: unsafe { mem::MaybeUninit::zeroed().assume_init() },
            optmask: 0,
            domains: vec![],
            lookups: None,
            #[cfg(cares115)]
            resolvconf_path: None,
            #[cfg(cares119)]
            hosts_path: None,
            socket_state_callback: None,
        }
    }
}

impl Options {
    /// Returns a fresh `Options`, on which no values are set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set flags controlling the behaviour of the resolver.  The available flags are documented
    /// [here](flags/index.html).
    pub fn set_flags(&mut self, flags: Flags) -> &mut Self {
        self.ares_options.flags = flags.bits();
        self.optmask |= c_ares_sys::ARES_OPT_FLAGS;
        self
    }

    /// Set the number of milliseconds each name server is given to respond to a query on the first
    /// try.  (After the first try, the timeout algorithm becomes more complicated, but scales
    /// linearly with the value of timeout).  The default is 2000ms.
    pub fn set_timeout(&mut self, ms: u32) -> &mut Self {
        self.ares_options.timeout = ms as c_int;
        self.optmask |= c_ares_sys::ARES_OPT_TIMEOUTMS;
        self
    }

    /// Set the number of tries the resolver will try contacting each name server before giving up.
    /// The default is three tries.
    pub fn set_tries(&mut self, tries: u32) -> &mut Self {
        self.ares_options.tries = tries as c_int;
        self.optmask |= c_ares_sys::ARES_OPT_TRIES;
        self
    }

    /// Set the number of dots which must be present in a domain name for it to be queried for "as
    /// is" prior to querying for it with the default domain extensions appended.  The default
    /// value is 1 unless set otherwise by resolv.conf or the RES_OPTIONS environment variable.
    pub fn set_ndots(&mut self, ndots: u32) -> &mut Self {
        self.ares_options.ndots = ndots as c_int;
        self.optmask |= c_ares_sys::ARES_OPT_NDOTS;
        self
    }

    /// Set the UDP port to use for queries.  The default value is 53, the standard name service
    /// port.
    pub fn set_udp_port(&mut self, udp_port: u16) -> &mut Self {
        self.ares_options.udp_port = udp_port;
        self.optmask |= c_ares_sys::ARES_OPT_UDP_PORT;
        self
    }

    /// Set the TCP port to use for queries.  The default value is 53, the standard name service
    /// port.
    pub fn set_tcp_port(&mut self, tcp_port: u16) -> &mut Self {
        self.ares_options.tcp_port = tcp_port;
        self.optmask |= c_ares_sys::ARES_OPT_TCP_PORT;
        self
    }

    /// Set the domains to search, instead of the domains specified in resolv.conf or the domain
    /// derived from the kernel hostname variable.
    pub fn set_domains(&mut self, domains: &[&str]) -> &mut Self {
        self.domains = domains.iter().map(|&s| CString::new(s).unwrap()).collect();
        self.optmask |= c_ares_sys::ARES_OPT_DOMAINS;
        self
    }

    /// Set the lookups to perform for host queries. `lookups` should be set to a string of the
    /// characters "b" or "f", where "b" indicates a DNS lookup and "f" indicates a lookup in the
    /// hosts file.
    pub fn set_lookups(&mut self, lookups: &str) -> &mut Self {
        let c_lookups = CString::new(lookups).unwrap();
        self.lookups = Some(c_lookups);
        self.optmask |= c_ares_sys::ARES_OPT_LOOKUPS;
        self
    }

    /// Set the callback function to be invoked when a socket changes state.
    ///
    /// `callback(socket, read, write)` will be called when a socket changes state:
    ///
    /// - `read` is set to true if the socket should listen for read events
    /// - `write` is set to true if the socket should listen for write events.
    pub fn set_socket_state_callback<F>(&mut self, callback: F) -> &mut Self
    where
        F: FnMut(Socket, bool, bool) + Send + 'static,
    {
        let boxed_callback = Arc::new(callback);
        self.ares_options.sock_state_cb = Some(socket_state_callback::<F>);
        self.ares_options.sock_state_cb_data = (&*boxed_callback as *const F).cast_mut().cast();
        self.socket_state_callback = Some(boxed_callback);
        self.optmask |= c_ares_sys::ARES_OPT_SOCK_STATE_CB;
        self
    }

    /// Set the socket send buffer size.
    pub fn set_sock_send_buffer_size(&mut self, size: u32) -> &mut Self {
        self.ares_options.socket_send_buffer_size = size as c_int;
        self.optmask |= c_ares_sys::ARES_OPT_SOCK_SNDBUF;
        self
    }

    /// Set the socket receive buffer size.
    pub fn set_sock_receive_buffer_size(&mut self, size: u32) -> &mut Self {
        self.ares_options.socket_receive_buffer_size = size as c_int;
        self.optmask |= c_ares_sys::ARES_OPT_SOCK_RCVBUF;
        self
    }

    /// Configure round robin selection of nameservers.
    pub fn set_rotate(&mut self) -> &mut Self {
        self.optmask &= !c_ares_sys::ARES_OPT_NOROTATE;
        self.optmask |= c_ares_sys::ARES_OPT_ROTATE;
        self
    }

    /// Prevent round robin selection of nameservers.
    pub fn set_no_rotate(&mut self) -> &mut Self {
        self.optmask &= !c_ares_sys::ARES_OPT_ROTATE;
        self.optmask |= c_ares_sys::ARES_OPT_NOROTATE;
        self
    }

    /// Set the EDNS packet size.
    pub fn set_ednspsz(&mut self, size: u32) -> &mut Self {
        self.ares_options.ednspsz = size as c_int;
        self.optmask |= c_ares_sys::ARES_OPT_EDNSPSZ;
        self
    }

    /// The path to use for reading the resolv.conf file.  The `resolvconf_path` should be set to a
    /// path string, and will be honoured on *nix like systems.  The default is /etc/resolv.conf.
    #[cfg(cares115)]
    pub fn set_resolvconf_path(&mut self, resolvconf_path: &str) -> &mut Self {
        let c_resolvconf_path = CString::new(resolvconf_path).unwrap();
        self.resolvconf_path = Some(c_resolvconf_path);
        self.optmask |= c_ares_sys::ARES_OPT_RESOLVCONF;
        self
    }

    /// The path to use for reading the hosts file.  The `hosts_path` should be set to a
    /// path string, and will be honoured on *nix like systems.  The default is /etc/hosts.
    #[cfg(cares119)]
    pub fn set_hosts_path(&mut self, hosts_path: &str) -> &mut Self {
        let c_hosts_path = CString::new(hosts_path).unwrap();
        self.hosts_path = Some(c_hosts_path);
        self.optmask |= c_ares_sys::ARES_OPT_HOSTS_FILE;
        self
    }

    /// The maximum number of udp queries that can be sent on a single ephemeral port to a given
    /// DNS server before a new ephemeral port is assigned.  Any value of 0 or less will be
    /// considered unlimited, and is the default.
    #[cfg(cares120)]
    pub fn set_udp_max_queries(&mut self, udp_max_queries: i32) -> &mut Self {
        self.ares_options.udp_max_queries = udp_max_queries;
        self.optmask |= c_ares_sys::ARES_OPT_UDP_MAX_QUERIES;
        self
    }
}

/// A channel for name service lookups.
pub struct Channel {
    ares_channel: c_ares_sys::ares_channel,
    phantom: PhantomData<c_ares_sys::ares_channeldata>,

    // For ownership only.
    _socket_state_callback: Option<Arc<SocketStateCallback>>,
}

impl Channel {
    /// Create a new channel for name service lookups, with default `Options`.
    pub fn new() -> Result<Self> {
        let options = Options::default();
        Self::with_options(options)
    }

    /// Create a new channel for name service lookups, with the given `Options`.
    pub fn with_options(mut options: Options) -> Result<Channel> {
        // Initialize the library.
        let ares_library_lock = ARES_LIBRARY_LOCK.lock().unwrap();
        let lib_rc = unsafe { c_ares_sys::ares_library_init(c_ares_sys::ARES_LIB_INIT_ALL) };
        std::mem::drop(ares_library_lock);
        if lib_rc != c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            return Err(Error::from(lib_rc));
        }

        // We deferred setting up domains in the options - do it now.
        let domains: Vec<_> = options.domains.iter().map(|s| s.as_ptr()).collect();
        options.ares_options.domains = domains.as_ptr().cast_mut().cast();
        options.ares_options.ndomains = domains.len() as c_int;

        // Likewise for lookups.
        for c_lookup in &options.lookups {
            options.ares_options.lookups = c_lookup.as_ptr().cast_mut()
        }

        // And the resolvconf_path.
        #[cfg(cares115)]
        for c_resolvconf_path in &options.resolvconf_path {
            options.ares_options.resolvconf_path = c_resolvconf_path.as_ptr().cast_mut()
        }

        // And the hosts_path.
        #[cfg(cares119)]
        for c_hosts_path in &options.hosts_path {
            options.ares_options.hosts_path = c_hosts_path.as_ptr().cast_mut()
        }

        // Initialize the channel.
        let mut ares_channel = ptr::null_mut();
        let channel_rc = unsafe {
            c_ares_sys::ares_init_options(
                &mut ares_channel,
                &mut options.ares_options,
                options.optmask,
            )
        };
        if channel_rc != c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            let ares_library_lock = ARES_LIBRARY_LOCK.lock().unwrap();
            unsafe { c_ares_sys::ares_library_cleanup() }
            std::mem::drop(ares_library_lock);
            return Err(Error::from(channel_rc));
        }

        let channel = Channel {
            ares_channel,
            phantom: PhantomData,
            _socket_state_callback: options.socket_state_callback,
        };
        Ok(channel)
    }

    /// Duplicate a channel.
    pub fn try_clone(&self) -> Result<Channel> {
        let mut ares_channel = ptr::null_mut();
        let rc = unsafe { c_ares_sys::ares_dup(&mut ares_channel, self.ares_channel) };
        if rc != c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            return Err(Error::from(rc));
        }

        let callback = self._socket_state_callback.as_ref().cloned();
        let channel = Channel {
            ares_channel,
            phantom: PhantomData,
            _socket_state_callback: callback,
        };
        Ok(channel)
    }

    /// Handle input, output, and timeout events associated with the specified file descriptors
    /// (sockets).
    ///
    /// Providing a value for `read_fd` indicates that the identified socket is readable; likewise
    /// providing a value for `write_fd` indicates that the identified socket is writable.  Use
    /// `SOCKET_BAD` for "no action".
    pub fn process_fd(&mut self, read_fd: Socket, write_fd: Socket) {
        unsafe { c_ares_sys::ares_process_fd(self.ares_channel, read_fd, write_fd) }
        panic::propagate();
    }

    /// Handle input and output events associated with the specified file descriptors (sockets).
    /// Also handles timeouts associated with the `Channel`.
    pub fn process(&mut self, read_fds: &mut c_types::fd_set, write_fds: &mut c_types::fd_set) {
        unsafe { c_ares_sys::ares_process(self.ares_channel, read_fds, write_fds) }
        panic::propagate();
    }

    /// Retrieve the set of socket descriptors which the calling application should wait on for
    /// reading and / or writing.
    pub fn get_sock(&self) -> GetSock {
        let mut socks = [0; c_ares_sys::ARES_GETSOCK_MAXNUM];
        let bitmask = unsafe {
            c_ares_sys::ares_getsock(
                self.ares_channel,
                socks.as_mut_ptr(),
                c_ares_sys::ARES_GETSOCK_MAXNUM as c_int,
            )
        };
        GetSock::new(socks, bitmask as u32)
    }

    /// Retrieve the set of socket descriptors which the calling application should wait on for
    /// reading and / or writing.
    pub fn fds(&self, read_fds: &mut c_types::fd_set, write_fds: &mut c_types::fd_set) -> u32 {
        unsafe { c_ares_sys::ares_fds(self.ares_channel, read_fds, write_fds) as u32 }
    }

    /// Set the list of servers to contact, instead of the servers specified in resolv.conf or the
    /// local named.
    ///
    /// String format is `host[:port]`.  IPv6 addresses with ports require square brackets eg
    /// `[2001:4860:4860::8888]:53`.
    pub fn set_servers(&mut self, servers: &[&str]) -> Result<&mut Self> {
        let servers_csv = servers.join(",");
        let c_servers = CString::new(servers_csv).unwrap();
        let ares_rc = unsafe {
            c_ares_sys::ares_set_servers_ports_csv(self.ares_channel, c_servers.as_ptr())
        };
        if ares_rc == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            Ok(self)
        } else {
            Err(Error::from(ares_rc))
        }
    }

    /// Set the local IPv4 address from which to make queries.
    pub fn set_local_ipv4(&mut self, ipv4: Ipv4Addr) -> &mut Self {
        unsafe { c_ares_sys::ares_set_local_ip4(self.ares_channel, u32::from(ipv4)) }
        self
    }

    /// Set the local IPv6 address from which to make queries.
    pub fn set_local_ipv6(&mut self, ipv6: &Ipv6Addr) -> &mut Self {
        let in6_addr = ipv6_as_in6_addr(ipv6);
        unsafe {
            c_ares_sys::ares_set_local_ip6(
                self.ares_channel,
                (&in6_addr as *const c_types::in6_addr).cast(),
            )
        }
        self
    }

    /// Set the local device from which to make queries.
    pub fn set_local_device(&mut self, device: &str) -> &mut Self {
        let c_dev = CString::new(device).unwrap();
        unsafe { c_ares_sys::ares_set_local_dev(self.ares_channel, c_dev.as_ptr()) }
        self
    }

    /// Initializes an address sortlist configuration, so that addresses returned by
    /// `get_host_by_name()` are sorted according to the sortlist.
    ///
    /// Each element of the sortlist holds an IP-address/netmask pair. The netmask is optional but
    /// follows the address after a slash if present. For example: "130.155.160.0/255.255.240.0",
    /// or "130.155.0.0".
    pub fn set_sortlist(&mut self, sortlist: &[&str]) -> Result<&mut Self> {
        let sortlist_str = sortlist.join(" ");
        let c_sortlist = CString::new(sortlist_str).unwrap();
        let ares_rc =
            unsafe { c_ares_sys::ares_set_sortlist(self.ares_channel, c_sortlist.as_ptr()) };
        if ares_rc == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            Ok(self)
        } else {
            Err(Error::from(ares_rc))
        }
    }

    /// Initiate a single-question DNS query for the A records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_a<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<AResults>) + Send + 'static,
    {
        ares_query!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::A,
            query_a_callback::<F>,
            handler
        );
    }

    /// Initiate a series of single-question DNS queries for the A records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_a<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<AResults>) + Send + 'static,
    {
        ares_search!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::A,
            query_a_callback::<F>,
            handler
        );
    }

    /// Initiate a single-question DNS query for the AAAA records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_aaaa<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<AAAAResults>) + Send + 'static,
    {
        ares_query!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::AAAA,
            query_aaaa_callback::<F>,
            handler
        );
    }

    /// Initiate a series of single-question DNS queries for the AAAA records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_aaaa<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<AAAAResults>) + Send + 'static,
    {
        ares_search!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::AAAA,
            query_aaaa_callback::<F>,
            handler
        );
    }

    /// Initiate a single-question DNS query for the CAA records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    #[cfg(cares117)]
    pub fn query_caa<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<CAAResults>) + Send + 'static,
    {
        ares_query!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::CAA,
            query_caa_callback::<F>,
            handler
        );
    }

    /// Initiate a series of single-question DNS queries for the CAA records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    #[cfg(cares117)]
    pub fn search_caa<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<CAAResults>) + Send + 'static,
    {
        ares_search!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::CAA,
            query_caa_callback::<F>,
            handler
        );
    }

    /// Initiate a single-question DNS query for the CNAME records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_cname<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<CNameResults>) + Send + 'static,
    {
        ares_query!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::CNAME,
            query_cname_callback::<F>,
            handler
        );
    }

    /// Initiate a series of single-question DNS queries for the CNAME records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_cname<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<CNameResults>) + Send + 'static,
    {
        ares_search!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::CNAME,
            query_cname_callback::<F>,
            handler
        );
    }

    /// Initiate a single-question DNS query for the MX records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_mx<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<MXResults>) + Send + 'static,
    {
        ares_query!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::MX,
            query_mx_callback::<F>,
            handler
        );
    }

    /// Initiate a series of single-question DNS queries for the MX records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_mx<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<MXResults>) + Send + 'static,
    {
        ares_search!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::MX,
            query_mx_callback::<F>,
            handler
        );
    }

    /// Initiate a single-question DNS query for the NAPTR records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_naptr<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<NAPTRResults>) + Send + 'static,
    {
        ares_query!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::NAPTR,
            query_naptr_callback::<F>,
            handler
        );
    }

    /// Initiate a series of single-question DNS queries for the NAPTR records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_naptr<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<NAPTRResults>) + Send + 'static,
    {
        ares_search!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::NAPTR,
            query_naptr_callback::<F>,
            handler
        );
    }

    /// Initiate a single-question DNS query for the NS records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_ns<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<NSResults>) + Send + 'static,
    {
        ares_query!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::NS,
            query_ns_callback::<F>,
            handler
        );
    }

    /// Initiate a series of single-question DNS queries for the NS records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_ns<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<NSResults>) + Send + 'static,
    {
        ares_search!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::NS,
            query_ns_callback::<F>,
            handler
        );
    }

    /// Initiate a single-question DNS query for the PTR records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_ptr<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<PTRResults>) + Send + 'static,
    {
        ares_query!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::PTR,
            query_ptr_callback::<F>,
            handler
        );
    }

    /// Initiate a series of single-question DNS queries for the PTR records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_ptr<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<PTRResults>) + Send + 'static,
    {
        ares_search!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::PTR,
            query_ptr_callback::<F>,
            handler
        );
    }

    /// Initiate a single-question DNS query for the SOA records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_soa<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<SOAResult>) + Send + 'static,
    {
        ares_query!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::SOA,
            query_soa_callback::<F>,
            handler
        );
    }

    /// Initiate a series of single-question DNS queries for the SOA records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_soa<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<SOAResult>) + Send + 'static,
    {
        ares_search!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::SOA,
            query_soa_callback::<F>,
            handler
        );
    }

    /// Initiate a single-question DNS query for the SRV records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_srv<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<SRVResults>) + Send + 'static,
    {
        ares_query!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::SRV,
            query_srv_callback::<F>,
            handler
        );
    }

    /// Initiate a series of single-question DNS queries for the SRV records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_srv<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<SRVResults>) + Send + 'static,
    {
        ares_search!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::SRV,
            query_srv_callback::<F>,
            handler
        );
    }

    /// Initiate a single-question DNS query for the TXT records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_txt<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<TXTResults>) + Send + 'static,
    {
        ares_query!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::TXT,
            query_txt_callback::<F>,
            handler
        );
    }

    /// Initiate a series of single-question DNS queries for the TXT records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_txt<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<TXTResults>) + Send + 'static,
    {
        ares_search!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::TXT,
            query_txt_callback::<F>,
            handler
        );
    }

    /// Initiate a single-question DNS query for the URI records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_uri<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<URIResults>) + Send + 'static,
    {
        ares_query!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::URI,
            query_uri_callback::<F>,
            handler
        );
    }

    /// Initiate a series of single-question DNS queries for the URI records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_uri<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<URIResults>) + Send + 'static,
    {
        ares_search!(
            self.ares_channel,
            name,
            DnsClass::IN,
            QueryType::URI,
            query_uri_callback::<F>,
            handler
        );
    }

    /// Perform a host query by address.
    ///
    /// On completion, `handler` is called with the result.
    pub fn get_host_by_address<F>(&mut self, address: &IpAddr, handler: F)
    where
        F: FnOnce(Result<HostResults>) + Send + 'static,
    {
        let in_addr: c_types::in_addr;
        let in6_addr: c_types::in6_addr;
        let c_addr = match *address {
            IpAddr::V4(v4) => {
                in_addr = ipv4_as_in_addr(v4);
                (&in_addr as *const c_types::in_addr).cast()
            }
            IpAddr::V6(ref v6) => {
                in6_addr = ipv6_as_in6_addr(v6);
                (&in6_addr as *const c_types::in6_addr).cast()
            }
        };
        let (family, length) = match *address {
            IpAddr::V4(_) => (AddressFamily::INET, mem::size_of::<c_types::in_addr>()),
            IpAddr::V6(_) => (AddressFamily::INET6, mem::size_of::<c_types::in6_addr>()),
        };
        let c_arg = Box::into_raw(Box::new(handler));
        unsafe {
            c_ares_sys::ares_gethostbyaddr(
                self.ares_channel,
                c_addr,
                length as c_int,
                family as c_int,
                Some(get_host_callback::<F>),
                c_arg.cast(),
            )
        }
        panic::propagate();
    }

    /// Perform a host query by name.
    ///
    /// On completion, `handler` is called with the result.
    pub fn get_host_by_name<F>(&mut self, name: &str, family: AddressFamily, handler: F)
    where
        F: FnOnce(Result<HostResults>) + Send + 'static,
    {
        let c_name = CString::new(name).unwrap();
        let c_arg = Box::into_raw(Box::new(handler));
        unsafe {
            c_ares_sys::ares_gethostbyname(
                self.ares_channel,
                c_name.as_ptr(),
                family as c_int,
                Some(get_host_callback::<F>),
                c_arg.cast(),
            )
        }
        panic::propagate();
    }

    /// Address-to-nodename translation in protocol-independent manner.
    ///
    /// The valid values for `flags` are documented [here](ni_flags/index.html).
    ///
    /// On completion, `handler` is called with the result.
    pub fn get_name_info<F>(&mut self, address: &SocketAddr, flags: NIFlags, handler: F)
    where
        F: FnOnce(Result<NameInfoResult>) + Send + 'static,
    {
        let sockaddr_in: c_types::sockaddr_in;
        let sockaddr_in6: c_types::sockaddr_in6;
        let c_addr = match *address {
            SocketAddr::V4(ref v4) => {
                sockaddr_in = socket_addrv4_as_sockaddr_in(v4);
                (&sockaddr_in as *const c_types::sockaddr_in).cast()
            }
            SocketAddr::V6(ref v6) => {
                sockaddr_in6 = socket_addrv6_as_sockaddr_in6(v6);
                (&sockaddr_in6 as *const c_types::sockaddr_in6).cast()
            }
        };
        let length = match *address {
            SocketAddr::V4(_) => mem::size_of::<c_types::sockaddr_in>(),
            SocketAddr::V6(_) => mem::size_of::<c_types::sockaddr_in6>(),
        };
        let c_arg = Box::into_raw(Box::new(handler));
        unsafe {
            c_ares_sys::ares_getnameinfo(
                self.ares_channel,
                c_addr,
                length as c_ares_sys::ares_socklen_t,
                flags.bits(),
                Some(get_name_info_callback::<F>),
                c_arg.cast(),
            )
        }
        panic::propagate();
    }

    /// Initiate a single-question DNS query for `name`.  The class and type of the query are per
    /// the provided parameters, taking values as defined in `arpa/nameser.h`.
    ///
    /// On completion, `handler` is called with the result.
    ///
    /// This method is provided so that users can query DNS types for which `c-ares` does not
    /// provide a parser.  This is expected to be a last resort; if a suitable `query_xxx()` is
    /// available, that should be preferred.
    pub fn query<F>(&mut self, name: &str, dns_class: u16, query_type: u16, handler: F)
    where
        F: FnOnce(Result<&[u8]>) + Send + 'static,
    {
        ares_query!(
            self.ares_channel,
            name,
            c_int::from(dns_class),
            c_int::from(query_type),
            query_callback::<F>,
            handler
        );
    }

    /// Initiate a series of single-question DNS queries for `name`.  The class and type of the
    /// query are per the provided parameters, taking values as defined in `arpa/nameser.h`.
    ///
    /// On completion, `handler` is called with the result.
    ///
    /// This method is provided so that users can search DNS types for which `c-ares` does not
    /// provide a parser.  This is expected to be a last resort; if a suitable `search_xxx()` is
    /// available, that should be preferred.
    pub fn search<F>(&mut self, name: &str, dns_class: u16, query_type: u16, handler: F)
    where
        F: FnOnce(Result<&[u8]>) + Send + 'static,
    {
        ares_search!(
            self.ares_channel,
            name,
            c_int::from(dns_class),
            c_int::from(query_type),
            query_callback::<F>,
            handler
        );
    }

    /// Cancel all requests made on this `Channel`.
    ///
    /// Callbacks will be invoked for each pending query, passing a result
    /// `Err(Error::ECANCELLED)`.
    pub fn cancel(&mut self) {
        unsafe { c_ares_sys::ares_cancel(self.ares_channel) }
        panic::propagate();
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        unsafe { c_ares_sys::ares_destroy(self.ares_channel) }
        let ares_library_lock = ARES_LIBRARY_LOCK.lock().unwrap();
        unsafe { c_ares_sys::ares_library_cleanup() }
        std::mem::drop(ares_library_lock);
        panic::propagate();
    }
}

unsafe impl Send for Channel {}
unsafe impl Sync for Channel {}
unsafe impl Send for Options {}
unsafe impl Sync for Options {}

unsafe extern "C" fn socket_state_callback<F>(
    data: *mut c_void,
    socket_fd: c_ares_sys::ares_socket_t,
    readable: c_int,
    writable: c_int,
) where
    F: FnMut(Socket, bool, bool) + Send + 'static,
{
    let handler = data.cast::<F>();
    panic::catch(|| (*handler)(socket_fd, readable != 0, writable != 0));
}

/// Information about the set of sockets that `c-ares` is interested in, as returned by
/// `get_sock()`.
#[derive(Clone, Copy, Debug)]
pub struct GetSock {
    socks: [c_ares_sys::ares_socket_t; c_ares_sys::ARES_GETSOCK_MAXNUM],
    bitmask: u32,
}

impl GetSock {
    fn new(
        socks: [c_ares_sys::ares_socket_t; c_ares_sys::ARES_GETSOCK_MAXNUM],
        bitmask: u32,
    ) -> Self {
        GetSock { socks, bitmask }
    }

    /// Returns an iterator over the sockets that `c-ares` is interested in.
    pub fn iter(&self) -> GetSockIter {
        GetSockIter {
            next: 0,
            getsock: self,
        }
    }
}

/// Iterator for sockets of interest to `c-ares`.
///
/// Iterator items are `(socket, readable, writable)`.
#[derive(Clone, Copy, Debug)]
pub struct GetSockIter<'a> {
    next: usize,
    getsock: &'a GetSock,
}

impl<'a> Iterator for GetSockIter<'a> {
    type Item = (Socket, bool, bool);
    fn next(&mut self) -> Option<Self::Item> {
        let index = self.next;
        self.next += 1;
        if index >= c_ares_sys::ARES_GETSOCK_MAXNUM {
            None
        } else {
            let bit = 1 << index;
            let readable = (self.getsock.bitmask & bit) != 0;
            let bit = bit << c_ares_sys::ARES_GETSOCK_MAXNUM;
            let writable = (self.getsock.bitmask & bit) != 0;
            if readable || writable {
                let fd = self.getsock.socks[index];
                Some((fd, readable, writable))
            } else {
                None
            }
        }
    }
}

impl<'a> IntoIterator for &'a GetSock {
    type Item = (Socket, bool, bool);
    type IntoIter = GetSockIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}
