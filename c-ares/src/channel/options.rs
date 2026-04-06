use core::ffi::c_int;
use std::ffi::CString;
use std::fmt;
use std::mem;
use std::sync::Arc;
use std::time::Duration;

use crate::Flags;
use crate::error::{Error, Result};
#[cfg(cares1_26)]
use crate::types::EventSys;
use crate::types::Socket;

pub(crate) type SocketStateCallback = dyn Fn(Socket, bool, bool) + Send + 'static;

/// Server failover options.
///
/// When a DNS server fails to respond to a query, c-ares will deprioritize the server.  On
/// subsequent queries, servers with fewer consecutive failures will be selected in preference.
/// However, in order to detect when such a server has recovered, c-ares will occasionally retry
/// failed servers.  `ServerFailoverOptions` contains options to control this behaviour.
#[cfg(cares1_29)]
#[derive(Debug)]
pub struct ServerFailoverOptions {
    retry_chance: u16,
    retry_delay: Duration,
}

#[cfg(cares1_29)]
impl Default for ServerFailoverOptions {
    fn default() -> Self {
        Self {
            retry_chance: 10,
            retry_delay: Duration::from_secs(5),
        }
    }
}

#[cfg(cares1_29)]
impl ServerFailoverOptions {
    /// Returns a new `ServerFailoverOptions`.
    pub fn new() -> Self {
        Self::default()
    }

    /// The `retry_chance` sets the probability (1/N) of retrying a failed server on any given
    /// query.  Setting to a value of 0 disables retries.
    pub fn set_retry_chance(&mut self, retry_chance: u16) -> &mut Self {
        self.retry_chance = retry_chance;
        self
    }

    /// The `retry_delay` sets the minimum delay that c-ares will wait before
    /// retrying a specific failed server.
    pub fn set_retry_delay(&mut self, retry_delay: Duration) -> &mut Self {
        self.retry_delay = retry_delay;
        self
    }
}

/// Used to configure the behaviour of the name resolver.
pub struct Options {
    pub(super) ares_options: c_ares_sys::ares_options,
    pub(super) optmask: c_int,
    pub(super) domains: Vec<CString>,
    pub(super) lookups: Option<CString>,
    pub(super) resolvconf_path: Option<CString>,
    #[cfg(cares1_19)]
    pub(super) hosts_path: Option<CString>,
    pub(super) socket_state_callback: Option<Arc<SocketStateCallback>>,
}

impl fmt::Debug for Options {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Options").finish_non_exhaustive()
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            ares_options: unsafe { mem::MaybeUninit::zeroed().assume_init() },
            optmask: 0,
            domains: vec![],
            lookups: None,
            resolvconf_path: None,
            #[cfg(cares1_19)]
            hosts_path: None,
            socket_state_callback: None,
        }
    }
}

impl Options {
    /// Returns a fresh `Options`, on which no values are set.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use c_ares::{Options, Flags};
    ///
    /// let mut options = Options::new();
    /// options.set_flags(Flags::STAYOPEN | Flags::EDNS)
    ///        .set_timeout(Duration::from_secs(5))
    ///        .set_tries(3);
    /// ```
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
    pub fn set_timeout(&mut self, timeout: Duration) -> &mut Self {
        self.ares_options.timeout = c_int::try_from(timeout.as_millis()).unwrap_or(c_int::MAX);
        self.optmask |= c_ares_sys::ARES_OPT_TIMEOUTMS;
        self
    }

    /// Set the number of tries the resolver will try contacting each name server before giving up.
    /// The default is three tries.
    pub fn set_tries(&mut self, tries: u32) -> &mut Self {
        self.ares_options.tries = c_int::try_from(tries).unwrap_or(c_int::MAX);
        self.optmask |= c_ares_sys::ARES_OPT_TRIES;
        self
    }

    /// Set the number of dots which must be present in a domain name for it to be queried for "as
    /// is" prior to querying for it with the default domain extensions appended.  The default
    /// value is 1 unless set otherwise by resolv.conf or the RES_OPTIONS environment variable.
    pub fn set_ndots(&mut self, ndots: u32) -> &mut Self {
        self.ares_options.ndots = c_int::try_from(ndots).unwrap_or(c_int::MAX);
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
    pub fn set_domains(&mut self, domains: &[&str]) -> Result<&mut Self> {
        self.domains = domains
            .iter()
            .map(|&s| CString::new(s).map_err(|_| Error::EBADSTR))
            .collect::<Result<Vec<_>>>()?;
        self.optmask |= c_ares_sys::ARES_OPT_DOMAINS;
        Ok(self)
    }

    /// Set the lookups to perform for host queries. `lookups` should be set to a string of the
    /// characters "b" or "f", where "b" indicates a DNS lookup and "f" indicates a lookup in the
    /// hosts file.
    pub fn set_lookups(&mut self, lookups: &str) -> Result<&mut Self> {
        let c_lookups = CString::new(lookups).map_err(|_| Error::EBADSTR)?;
        self.lookups = Some(c_lookups);
        self.optmask |= c_ares_sys::ARES_OPT_LOOKUPS;
        Ok(self)
    }

    /// Set the callback function to be invoked when a socket changes state.
    ///
    /// `callback(socket, read, write)` will be called when a socket changes state:
    ///
    /// - `read` is set to true if the socket should listen for read events
    /// - `write` is set to true if the socket should listen for write events.
    pub fn set_socket_state_callback<F>(&mut self, callback: F) -> &mut Self
    where
        F: Fn(Socket, bool, bool) + Send + 'static,
    {
        let boxed_callback = Arc::new(callback);
        self.ares_options.sock_state_cb = Some(super::socket_state_callback::<F>);
        self.ares_options.sock_state_cb_data = Arc::as_ptr(&boxed_callback).cast_mut().cast();
        self.socket_state_callback = Some(boxed_callback);
        self.optmask |= c_ares_sys::ARES_OPT_SOCK_STATE_CB;
        self
    }

    /// Set the socket send buffer size.
    pub fn set_sock_send_buffer_size(&mut self, size: u32) -> &mut Self {
        self.ares_options.socket_send_buffer_size = c_int::try_from(size).unwrap_or(c_int::MAX);
        self.optmask |= c_ares_sys::ARES_OPT_SOCK_SNDBUF;
        self
    }

    /// Set the socket receive buffer size.
    pub fn set_sock_receive_buffer_size(&mut self, size: u32) -> &mut Self {
        self.ares_options.socket_receive_buffer_size = c_int::try_from(size).unwrap_or(c_int::MAX);
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
        self.ares_options.ednspsz = c_int::try_from(size).unwrap_or(c_int::MAX);
        self.optmask |= c_ares_sys::ARES_OPT_EDNSPSZ;
        self
    }

    /// Set the path to use for reading the resolv.conf file.  The `resolvconf_path` should be set
    /// to a path string, and will be honoured on *nix like systems.  The default is
    /// /etc/resolv.conf.
    pub fn set_resolvconf_path(&mut self, resolvconf_path: &str) -> Result<&mut Self> {
        let c_resolvconf_path = CString::new(resolvconf_path).map_err(|_| Error::EBADSTR)?;
        self.resolvconf_path = Some(c_resolvconf_path);
        self.optmask |= c_ares_sys::ARES_OPT_RESOLVCONF;
        Ok(self)
    }

    /// Set the path to use for reading the hosts file.  The `hosts_path` should be set to a path
    /// string, and will be honoured on *nix like systems.  The default is /etc/hosts.
    #[cfg(cares1_19)]
    pub fn set_hosts_path(&mut self, hosts_path: &str) -> Result<&mut Self> {
        let c_hosts_path = CString::new(hosts_path).map_err(|_| Error::EBADSTR)?;
        self.hosts_path = Some(c_hosts_path);
        self.optmask |= c_ares_sys::ARES_OPT_HOSTS_FILE;
        Ok(self)
    }

    /// Set the maximum number of UDP queries that can be sent on a single ephemeral port to a
    /// given DNS server before a new ephemeral port is assigned.
    ///
    /// Pass `None` for unlimited (the default).
    #[cfg(cares1_20)]
    pub fn set_udp_max_queries(&mut self, udp_max_queries: Option<u32>) -> &mut Self {
        self.ares_options.udp_max_queries = match udp_max_queries {
            None => 0,
            Some(n) => c_int::try_from(n).unwrap_or(c_int::MAX),
        };
        self.optmask |= c_ares_sys::ARES_OPT_UDP_MAX_QUERIES;
        self
    }

    /// Set the upper bound for timeout between sequential retry attempts.  When retrying queries,
    /// the timeout is increased from the requested timeout parameter, this caps the value.
    #[cfg(cares1_22)]
    pub fn set_max_timeout(&mut self, max_timeout: Duration) -> &mut Self {
        self.ares_options.maxtimeout =
            c_int::try_from(max_timeout.as_millis()).unwrap_or(c_int::MAX);
        self.optmask |= c_ares_sys::ARES_OPT_MAXTIMEOUTMS;
        self
    }

    /// Enable the built-in query cache.  Will cache queries based on the returned TTL in the DNS
    /// message.  Only fully successful and NXDOMAIN query results will be cached.
    ///
    /// The provided value is the maximum number of seconds a query result may be cached; this will
    /// override a larger TTL in the response message. This must be a non-zero value otherwise the
    /// cache will be disabled.
    #[cfg(cares1_23)]
    pub fn set_query_cache_max_ttl(&mut self, qcache_max_ttl: u32) -> &mut Self {
        self.ares_options.qcache_max_ttl = qcache_max_ttl;
        self.optmask |= c_ares_sys::ARES_OPT_QUERY_CACHE;
        self
    }

    /// Set server failover options.
    ///
    /// If this option is not specified then c-ares will use a probability of 10% and a minimum
    /// delay of 5 seconds.
    #[cfg(cares1_29)]
    pub fn set_server_failover_options(
        &mut self,
        server_failover_options: &ServerFailoverOptions,
    ) -> &mut Self {
        self.ares_options.server_failover_opts.retry_chance = server_failover_options.retry_chance;
        self.ares_options.server_failover_opts.retry_delay =
            server_failover_options.retry_delay.as_millis() as usize;
        self.optmask |= c_ares_sys::ARES_OPT_SERVER_FAILOVER;
        self
    }

    /// Enable the c-ares built-in event thread.
    ///
    /// When enabled, c-ares manages its own event loop internally.  The caller does not need to
    /// monitor sockets or call `process_fd()`.  Requires that c-ares was built with thread safety
    /// (`ares_threadsafety()` returns true); otherwise channel initialisation will fail.
    ///
    /// `evsys` selects the I/O backend; use [`EventSys::Default`] to let c-ares choose the best
    /// option for the platform.
    #[cfg(cares1_26)]
    pub fn set_event_thread(&mut self, evsys: EventSys) -> &mut Self {
        self.ares_options.evsys = evsys.into();
        self.optmask |= c_ares_sys::ARES_OPT_EVENT_THREAD;
        self
    }
}

unsafe impl Send for Options {}
unsafe impl Sync for Options {}

#[cfg(test)]
mod tests {
    use super::super::Channel;
    use super::*;

    #[test]
    fn options_default() {
        let _options = Options::new();
    }

    #[test]
    fn options_set_flags() {
        let mut options = Options::new();
        options.set_flags(Flags::USEVC | Flags::STAYOPEN);
    }

    #[test]
    fn options_set_timeout() {
        let mut options = Options::new();
        options.set_timeout(Duration::from_secs(5));
    }

    #[test]
    fn options_set_tries() {
        let mut options = Options::new();
        options.set_tries(5);
    }

    #[test]
    fn options_set_ndots() {
        let mut options = Options::new();
        options.set_ndots(2);
    }

    #[test]
    fn options_set_ports() {
        let mut options = Options::new();
        options.set_udp_port(53);
        options.set_tcp_port(53);
    }

    #[test]
    fn options_set_domains() {
        let mut options = Options::new();
        options.set_domains(&["example.com", "test.local"]).unwrap();
    }

    #[test]
    fn options_set_lookups() {
        let mut options = Options::new();
        options.set_lookups("bf").unwrap();
    }

    #[test]
    fn options_set_socket_state_callback() {
        let mut options = Options::new();
        options.set_socket_state_callback(|_socket, _read, _write| {});
    }

    #[test]
    fn options_set_sock_buffer_sizes() {
        let mut options = Options::new();
        options.set_sock_send_buffer_size(65536);
        options.set_sock_receive_buffer_size(65536);
    }

    #[test]
    fn options_set_rotate() {
        let mut options = Options::new();
        options.set_rotate();
    }

    #[test]
    fn options_set_no_rotate() {
        let mut options = Options::new();
        options.set_no_rotate();
    }

    #[test]
    fn options_set_ednspsz() {
        let mut options = Options::new();
        options.set_ednspsz(4096);
    }

    #[test]
    fn options_set_resolvconf_path() {
        let mut options = Options::new();
        options.set_resolvconf_path("/etc/resolv.conf").unwrap();
    }

    #[cfg(cares1_19)]
    #[test]
    fn options_set_hosts_path() {
        let mut options = Options::new();
        options.set_hosts_path("/etc/hosts").unwrap();
    }

    #[cfg(cares1_20)]
    #[test]
    fn options_set_udp_max_queries() {
        let mut options = Options::new();
        options.set_udp_max_queries(Some(100));
    }

    #[cfg(cares1_20)]
    #[test]
    fn options_set_udp_max_queries_none() {
        let mut options = Options::new();
        options.set_udp_max_queries(None);
    }

    #[cfg(cares1_22)]
    #[test]
    fn options_set_max_timeout() {
        let mut options = Options::new();
        options.set_max_timeout(Duration::from_secs(30));
    }

    #[cfg(cares1_23)]
    #[test]
    fn options_set_query_cache_max_ttl() {
        let mut options = Options::new();
        options.set_query_cache_max_ttl(3600);
    }

    #[cfg(cares1_29)]
    #[test]
    fn options_set_server_failover_options() {
        let mut options = Options::new();
        let mut failover_opts = ServerFailoverOptions::new();
        failover_opts
            .set_retry_chance(5)
            .set_retry_delay(Duration::from_secs(10));
        options.set_server_failover_options(&failover_opts);
    }

    #[test]
    fn options_builder_chain() {
        let mut options = Options::new();
        options
            .set_flags(Flags::USEVC)
            .set_timeout(Duration::from_secs(3))
            .set_tries(2)
            .set_ndots(1)
            .set_udp_port(53)
            .set_tcp_port(53)
            .set_lookups("b")
            .unwrap();
    }

    #[test]
    fn options_full_builder_chain() {
        let mut options = Options::new();
        options
            .set_flags(Flags::USEVC | Flags::STAYOPEN)
            .set_timeout(Duration::from_secs(2))
            .set_tries(3)
            .set_ndots(2)
            .set_udp_port(53)
            .set_tcp_port(53)
            .set_domains(&["example.com"])
            .unwrap()
            .set_lookups("b")
            .unwrap()
            .set_sock_send_buffer_size(32768)
            .set_sock_receive_buffer_size(32768)
            .set_rotate()
            .set_ednspsz(4096)
            .set_resolvconf_path("/etc/resolv.conf")
            .unwrap();
        let channel = Channel::with_options(options);
        assert!(channel.is_ok());
    }

    #[test]
    fn options_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Options>();
    }

    #[test]
    fn options_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Options>();
    }

    #[test]
    fn options_with_socket_callback_creates_channel() {
        let mut options = Options::new();
        options.set_socket_state_callback(|_socket, _read, _write| {
            // This callback would be invoked when socket state changes
        });
        let channel = Channel::with_options(options);
        assert!(channel.is_ok());
    }

    #[cfg(cares1_19)]
    #[test]
    fn options_hosts_path_creates_channel() {
        let mut options = Options::new();
        options.set_hosts_path("/etc/hosts").unwrap();
        let channel = Channel::with_options(options);
        assert!(channel.is_ok());
    }

    #[test]
    fn debug_options() {
        let options = Options::new();
        let debug = format!("{:?}", options);
        assert!(debug.contains("Options"));
    }

    #[test]
    #[cfg(cares1_29)]
    fn debug_server_failover_options() {
        let opts = ServerFailoverOptions::new();
        let debug = format!("{:?}", opts);
        assert!(debug.contains("ServerFailoverOptions"));
    }

    #[cfg(cares1_26)]
    #[test]
    fn options_set_event_thread() {
        let mut options = Options::new();
        options.set_event_thread(EventSys::Default);
    }

    #[cfg(cares1_26)]
    #[test]
    fn options_set_event_thread_creates_channel() {
        // Only works if c-ares was built with thread safety.
        if !crate::thread_safety() {
            return;
        }
        let mut options = Options::new();
        options.set_event_thread(EventSys::Default);
        let channel = Channel::with_options(options);
        assert!(channel.is_ok());
    }
}
