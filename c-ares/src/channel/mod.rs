#[allow(unused_imports)]
use core::ffi::{c_char, c_int, c_void};
use std::ffi::CString;
use std::fmt;
use std::mem;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ptr;
use std::sync::Arc;
use std::time::Duration;

mod options;
mod sockets;

pub use options::Options;
#[cfg(cares1_29)]
pub use options::ServerFailoverOptions;
pub use sockets::{Sockets, SocketsIter};

use options::SocketStateCallback;

#[cfg(cares1_29)]
use crate::ServerStateFlags;
use crate::a::AResults;
use crate::aaaa::AAAAResults;
use crate::addrinfo::{AddrInfoHints, AddrInfoResults, get_addrinfo_callback};
use crate::caa::CAAResults;
use crate::cname::CNameResults;
#[cfg(cares1_28)]
use crate::dns::callback::dnsrec_callback;
#[cfg(cares1_28)]
use crate::dns::{DnsCls, DnsRecord, DnsRecordType};
use crate::error::{Error, Result};
#[cfg(cares1_34)]
use crate::events::{FdEvents, ProcessFlags};
use crate::host::HostResults;
use crate::host::get_host_callback;
use crate::mx::MXResults;
use crate::nameinfo::{NameInfoResult, get_name_info_callback};
use crate::naptr::NAPTRResults;
use crate::ni_flags::NIFlags;
use crate::ns::NSResults;
use crate::panic;
use crate::ptr::PTRResults;
use crate::query::{query_callback, raw_query_callback};
use crate::record::QueryRecord;
use crate::soa::SOAResult;
use crate::srv::SRVResults;
#[cfg(cares1_24)]
use crate::string::AresString;
use crate::txt::TXTResults;
use crate::types::{AddressFamily, DnsClass, Socket};
use crate::uri::URIResults;
#[allow(unused_imports)]
use crate::utils::{
    c_string_as_str_unchecked, ipv4_as_in_addr, ipv6_as_in6_addr, socket_addrv4_as_sockaddr_in,
    socket_addrv6_as_sockaddr_in6, status_to_result,
};
use std::sync::Mutex;

// ares_library_init is not thread-safe, so we put a lock around it.
static ARES_LIBRARY_LOCK: Mutex<()> = Mutex::new(());

#[cfg(cares1_29)]
type ServerStateCallback = dyn Fn(&str, bool, ServerStateFlags) + Send + Sync + 'static;

#[cfg(cares1_34)]
type PendingWriteCallback = dyn Fn() + Send + Sync + 'static;

/// A channel for name service lookups.
pub struct Channel {
    ares_channel: c_ares_sys::ares_channel,

    // For ownership only.
    _socket_state_callback: Option<Arc<SocketStateCallback>>,

    // For ownership only.
    #[cfg(cares1_29)]
    _server_state_callback: Option<Arc<ServerStateCallback>>,

    // For ownership only.
    #[cfg(cares1_34)]
    _pending_write_callback: Option<Arc<PendingWriteCallback>>,
}

impl Channel {
    /// Returns the raw `ares_channel` pointer.
    ///
    /// # Safety
    ///
    /// The returned pointer is only valid for the lifetime of this `Channel`.
    /// Callers must ensure that any use of the pointer is compatible with
    /// concurrent access (e.g. only call thread-safe c-ares functions).
    pub fn as_raw(&self) -> c_ares_sys::ares_channel {
        self.ares_channel
    }

    /// Create a new channel for name service lookups, with default `Options`.
    ///
    /// # Examples
    ///
    /// ```
    /// let channel = c_ares::Channel::new().unwrap();
    /// ```
    pub fn new() -> Result<Self> {
        let options = Options::default();
        Self::with_options(options)
    }

    /// Create a new channel for name service lookups, with the given `Options`.
    ///
    /// # Examples
    ///
    /// ```
    /// let mut options = c_ares::Options::new();
    /// options.set_flags(c_ares::Flags::STAYOPEN)
    ///        .set_tries(2);
    /// let channel = c_ares::Channel::with_options(options).unwrap();
    /// ```
    pub fn with_options(mut options: Options) -> Result<Channel> {
        // Initialize the library.
        let lib_rc = {
            let _lock = ARES_LIBRARY_LOCK.lock().unwrap();
            unsafe { c_ares_sys::ares_library_init(c_ares_sys::ARES_LIB_INIT_ALL) }
        };
        if lib_rc != c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            return Err(Error::from(lib_rc));
        }

        // We deferred setting up domains in the options - do it now.
        let domains: Vec<_> = options.domains.iter().map(|s| s.as_ptr()).collect();
        options.ares_options.domains = domains.as_ptr().cast_mut().cast();
        options.ares_options.ndomains = domains.len() as i32;

        // Likewise for lookups.
        if let Some(c_lookup) = &options.lookups {
            options.ares_options.lookups = c_lookup.as_ptr().cast_mut()
        }

        // And the resolvconf_path.
        if let Some(c_resolvconf_path) = &options.resolvconf_path {
            options.ares_options.resolvconf_path = c_resolvconf_path.as_ptr().cast_mut()
        }

        // And the hosts_path.
        #[cfg(cares1_19)]
        if let Some(c_hosts_path) = &options.hosts_path {
            options.ares_options.hosts_path = c_hosts_path.as_ptr().cast_mut()
        }

        // Initialize the channel.
        let mut ares_channel = ptr::null_mut();
        let channel_rc = unsafe {
            c_ares_sys::ares_init_options(&mut ares_channel, &options.ares_options, options.optmask)
        };
        if channel_rc != c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            let _lock = ARES_LIBRARY_LOCK.lock().unwrap();
            unsafe { c_ares_sys::ares_library_cleanup() }
            return Err(Error::from(channel_rc));
        }

        let channel = Channel {
            ares_channel,
            _socket_state_callback: options.socket_state_callback,
            #[cfg(cares1_29)]
            _server_state_callback: None,
            #[cfg(cares1_34)]
            _pending_write_callback: None,
        };
        Ok(channel)
    }

    /// Reinitialize a channel from system configuration.
    #[cfg(cares1_22)]
    pub fn reinit(&mut self) -> Result<&mut Self> {
        let rc = unsafe { c_ares_sys::ares_reinit(self.ares_channel) };
        panic::propagate();
        status_to_result(rc)?;
        Ok(self)
    }

    /// Duplicate a channel.
    pub fn try_clone(&self) -> Result<Channel> {
        // Balance the ares_library_cleanup() that will run when the clone is dropped.
        let lib_rc = {
            let _lock = ARES_LIBRARY_LOCK.lock().unwrap();
            unsafe { c_ares_sys::ares_library_init(c_ares_sys::ARES_LIB_INIT_ALL) }
        };
        if lib_rc != c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            return Err(Error::from(lib_rc));
        }

        let mut ares_channel = ptr::null_mut();
        let rc = unsafe { c_ares_sys::ares_dup(&mut ares_channel, self.ares_channel) };
        if rc != c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            let _lock = ARES_LIBRARY_LOCK.lock().unwrap();
            unsafe { c_ares_sys::ares_library_cleanup() }
            return Err(Error::from(rc));
        }

        let socket_state_callback = self._socket_state_callback.as_ref().cloned();

        #[cfg(cares1_29)]
        let server_state_callback = self._server_state_callback.as_ref().cloned();

        #[cfg(cares1_34)]
        let pending_write_callback = self._pending_write_callback.as_ref().cloned();

        let channel = Channel {
            ares_channel,
            _socket_state_callback: socket_state_callback,
            #[cfg(cares1_29)]
            _server_state_callback: server_state_callback,
            #[cfg(cares1_34)]
            _pending_write_callback: pending_write_callback,
        };
        Ok(channel)
    }

    /// Handle input, output, and timeout events associated with the specified file descriptors
    /// (sockets).
    ///
    /// Providing a value for `read_fd` indicates that the identified socket is readable; likewise
    /// providing a value for `write_fd` indicates that the identified socket is writable.  Use
    /// `None` for "no action".
    pub fn process_fd(&mut self, read_fd: Option<Socket>, write_fd: Option<Socket>) {
        let rfd = read_fd.unwrap_or(c_ares_sys::ARES_SOCKET_BAD);
        let wfd = write_fd.unwrap_or(c_ares_sys::ARES_SOCKET_BAD);
        unsafe { c_ares_sys::ares_process_fd(self.ares_channel, rfd, wfd) }
        panic::propagate();
    }

    /// Handle input and output events associated with the specified file descriptors (sockets).
    /// Also handles timeouts associated with the `Channel`.
    pub fn process(&mut self, read_fds: &mut c_types::fd_set, write_fds: &mut c_types::fd_set) {
        unsafe { c_ares_sys::ares_process(self.ares_channel, read_fds, write_fds) }
        panic::propagate();
    }

    /// Process events on multiple file descriptors based on the event mask associated with each
    /// file descriptor.  Recommended over calling `process_fd()` multiple times since it would
    /// trigger additional logic such as timeout processing on each call.
    #[cfg(cares1_34)]
    pub fn process_fds(&mut self, events: &[FdEvents], flags: ProcessFlags) -> Result<()> {
        let rc = unsafe {
            c_ares_sys::ares_process_fds(
                self.ares_channel,
                events.as_ptr().cast(),
                events.len(),
                flags.bits(),
            )
        };
        panic::propagate();
        status_to_result(rc)
    }

    /// Retrieve the set of socket descriptors which the calling application should wait on for
    /// reading and / or writing.
    ///
    /// # Examples
    ///
    /// ```
    /// let channel = c_ares::Channel::new().unwrap();
    /// for (socket, readable, writable) in &channel.sockets() {
    ///     println!("socket {socket}: read={readable}, write={writable}");
    /// }
    /// ```
    pub fn sockets(&self) -> Sockets {
        let mut socks = [0; c_ares_sys::ARES_GETSOCK_MAXNUM];
        let bitmask = unsafe {
            c_ares_sys::ares_getsock(
                self.ares_channel,
                socks.as_mut_ptr(),
                c_ares_sys::ARES_GETSOCK_MAXNUM as i32,
            )
        };
        Sockets::new(socks, bitmask as u32)
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
    ///
    /// # Examples
    ///
    /// ```
    /// let mut channel = c_ares::Channel::new().unwrap();
    /// channel.set_servers(&["8.8.8.8", "8.8.4.4:53"]).unwrap();
    /// ```
    pub fn set_servers(&mut self, servers: &[&str]) -> Result<&mut Self> {
        let servers_csv = servers.join(",");
        let c_servers = CString::new(servers_csv).map_err(|_| Error::EBADSTR)?;
        let ares_rc = unsafe {
            c_ares_sys::ares_set_servers_ports_csv(self.ares_channel, c_servers.as_ptr())
        };
        if ares_rc == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            Ok(self)
        } else {
            Err(Error::from(ares_rc))
        }
    }

    /// Retrieves the list of configured servers.
    ///
    /// Each entry is in `host[:port]` format, matching what [`set_servers`](Self::set_servers)
    /// accepts.
    #[cfg(cares1_24)]
    pub fn servers(&self) -> Vec<String> {
        let csv = unsafe { c_ares_sys::ares_get_servers_csv(self.ares_channel) };
        let csv = AresString::new(csv);
        let csv: &str = &csv;
        if csv.is_empty() {
            Vec::new()
        } else {
            csv.split(',').map(String::from).collect()
        }
    }

    /// Set the local IPv4 address from which to make queries.
    pub fn set_local_ipv4(&mut self, ipv4: Ipv4Addr) -> &mut Self {
        unsafe { c_ares_sys::ares_set_local_ip4(self.ares_channel, u32::from(ipv4)) }
        self
    }

    /// Set the local IPv6 address from which to make queries.
    pub fn set_local_ipv6(&mut self, ipv6: Ipv6Addr) -> &mut Self {
        let in6_addr = ipv6_as_in6_addr(&ipv6);
        unsafe {
            c_ares_sys::ares_set_local_ip6(self.ares_channel, ptr::from_ref(&in6_addr).cast())
        }
        self
    }

    /// Set the local device from which to make queries.
    pub fn set_local_device(&mut self, device: &str) -> Result<&mut Self> {
        let c_dev = CString::new(device).map_err(|_| Error::EBADSTR)?;
        unsafe { c_ares_sys::ares_set_local_dev(self.ares_channel, c_dev.as_ptr()) }
        Ok(self)
    }

    /// Initializes an address sortlist configuration, so that addresses returned by
    /// `get_host_by_name()` are sorted according to the sortlist.
    ///
    /// Each element of the sortlist holds an IP-address/netmask pair. The netmask is optional but
    /// follows the address after a slash if present. For example: "130.155.160.0/255.255.240.0",
    /// or "130.155.0.0".
    pub fn set_sortlist(&mut self, sortlist: &[&str]) -> Result<&mut Self> {
        let sortlist_str = sortlist.join(" ");
        let c_sortlist = CString::new(sortlist_str).map_err(|_| Error::EBADSTR)?;
        let ares_rc =
            unsafe { c_ares_sys::ares_set_sortlist(self.ares_channel, c_sortlist.as_ptr()) };
        if ares_rc == c_ares_sys::ares_status_t::ARES_SUCCESS as i32 {
            Ok(self)
        } else {
            Err(Error::from(ares_rc))
        }
    }

    /// Set a callback function to be invoked whenever a query on the channel completes.
    ///
    /// `callback(server, success, flags)` will be called when a query completes.
    ///
    /// - `server` indicates the DNS server that was used for the query.
    /// - `success` indicates whether the query succeeded or not.
    /// - `flags` is a bitmask of flags describing various aspects of the query.
    #[cfg(cares1_29)]
    pub fn set_server_state_callback<F>(&mut self, callback: F) -> &mut Self
    where
        F: Fn(&str, bool, ServerStateFlags) + Send + Sync + 'static,
    {
        let boxed_callback = Arc::new(callback);
        let data = Arc::as_ptr(&boxed_callback).cast_mut().cast();
        unsafe {
            c_ares_sys::ares_set_server_state_callback(
                self.ares_channel,
                Some(server_state_callback::<F>),
                data,
            )
        }
        self._server_state_callback = Some(boxed_callback);
        self
    }

    /// Set a callback function to be invoked when there is potential pending data
    /// which needs to be written.
    #[cfg(cares1_34)]
    pub fn set_pending_write_callback<F>(&mut self, callback: F) -> &mut Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        let boxed_callback = Arc::new(callback);
        let data = Arc::as_ptr(&boxed_callback).cast_mut().cast();
        unsafe {
            c_ares_sys::ares_set_pending_write_cb(
                self.ares_channel,
                Some(pending_write_callback::<F>),
                data,
            )
        }
        self._pending_write_callback = Some(boxed_callback);
        self
    }

    /// Initiate a single-question DNS query for the A records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_a<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<AResults>) + Send + 'static,
    {
        self.do_query(name, handler);
    }

    /// Initiate a series of single-question DNS queries for the A records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_a<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<AResults>) + Send + 'static,
    {
        self.do_search(name, handler);
    }

    /// Initiate a single-question DNS query for the AAAA records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_aaaa<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<AAAAResults>) + Send + 'static,
    {
        self.do_query(name, handler);
    }

    /// Initiate a series of single-question DNS queries for the AAAA records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_aaaa<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<AAAAResults>) + Send + 'static,
    {
        self.do_search(name, handler);
    }

    /// Initiate a single-question DNS query for the CAA records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_caa<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<CAAResults>) + Send + 'static,
    {
        self.do_query(name, handler);
    }

    /// Initiate a series of single-question DNS queries for the CAA records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_caa<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<CAAResults>) + Send + 'static,
    {
        self.do_search(name, handler);
    }

    /// Initiate a single-question DNS query for the CNAME records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_cname<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<CNameResults>) + Send + 'static,
    {
        self.do_query(name, handler);
    }

    /// Initiate a series of single-question DNS queries for the CNAME records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_cname<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<CNameResults>) + Send + 'static,
    {
        self.do_search(name, handler);
    }

    /// Initiate a single-question DNS query for the MX records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_mx<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<MXResults>) + Send + 'static,
    {
        self.do_query(name, handler);
    }

    /// Initiate a series of single-question DNS queries for the MX records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_mx<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<MXResults>) + Send + 'static,
    {
        self.do_search(name, handler);
    }

    /// Initiate a single-question DNS query for the NAPTR records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_naptr<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<NAPTRResults>) + Send + 'static,
    {
        self.do_query(name, handler);
    }

    /// Initiate a series of single-question DNS queries for the NAPTR records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_naptr<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<NAPTRResults>) + Send + 'static,
    {
        self.do_search(name, handler);
    }

    /// Initiate a single-question DNS query for the NS records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_ns<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<NSResults>) + Send + 'static,
    {
        self.do_query(name, handler);
    }

    /// Initiate a series of single-question DNS queries for the NS records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_ns<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<NSResults>) + Send + 'static,
    {
        self.do_search(name, handler);
    }

    /// Initiate a single-question DNS query for the PTR records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_ptr<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<PTRResults>) + Send + 'static,
    {
        self.do_query(name, handler);
    }

    /// Initiate a series of single-question DNS queries for the PTR records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_ptr<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<PTRResults>) + Send + 'static,
    {
        self.do_search(name, handler);
    }

    /// Initiate a single-question DNS query for the SOA records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_soa<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<SOAResult>) + Send + 'static,
    {
        self.do_query(name, handler);
    }

    /// Initiate a series of single-question DNS queries for the SOA records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_soa<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<SOAResult>) + Send + 'static,
    {
        self.do_search(name, handler);
    }

    /// Initiate a single-question DNS query for the SRV records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_srv<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<SRVResults>) + Send + 'static,
    {
        self.do_query(name, handler);
    }

    /// Initiate a series of single-question DNS queries for the SRV records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_srv<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<SRVResults>) + Send + 'static,
    {
        self.do_search(name, handler);
    }

    /// Initiate a single-question DNS query for the TXT records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_txt<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<TXTResults>) + Send + 'static,
    {
        self.do_query(name, handler);
    }

    /// Initiate a series of single-question DNS queries for the TXT records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_txt<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<TXTResults>) + Send + 'static,
    {
        self.do_search(name, handler);
    }

    /// Initiate a single-question DNS query for the URI records associated with `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn query_uri<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<URIResults>) + Send + 'static,
    {
        self.do_query(name, handler);
    }

    /// Initiate a series of single-question DNS queries for the URI records associated with
    /// `name`.
    ///
    /// On completion, `handler` is called with the result.
    pub fn search_uri<F>(&mut self, name: &str, handler: F)
    where
        F: FnOnce(Result<URIResults>) + Send + 'static,
    {
        self.do_search(name, handler);
    }

    fn do_query<R, F>(&mut self, name: &str, handler: F)
    where
        R: QueryRecord,
        F: FnOnce(Result<R>) + Send + 'static,
    {
        ares_query!(
            self.ares_channel,
            name,
            DnsClass::IN,
            R::QUERY_TYPE,
            query_callback::<R, F>,
            handler
        );
    }

    fn do_search<R, F>(&mut self, name: &str, handler: F)
    where
        R: QueryRecord,
        F: FnOnce(Result<R>) + Send + 'static,
    {
        ares_search!(
            self.ares_channel,
            name,
            DnsClass::IN,
            R::QUERY_TYPE,
            query_callback::<R, F>,
            handler
        );
    }

    /// Perform a host query by address.
    ///
    /// On completion, `handler` is called with the result.
    pub fn get_host_by_address<F>(&mut self, address: &IpAddr, handler: F)
    where
        F: FnOnce(Result<&HostResults>) + Send + 'static,
    {
        let in_addr: c_types::in_addr;
        let in6_addr: c_types::in6_addr;
        let c_addr = match *address {
            IpAddr::V4(v4) => {
                in_addr = ipv4_as_in_addr(v4);
                ptr::from_ref(&in_addr).cast()
            }
            IpAddr::V6(ref v6) => {
                in6_addr = ipv6_as_in6_addr(v6);
                ptr::from_ref(&in6_addr).cast()
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
                length as i32,
                family as i32,
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
        F: FnOnce(Result<&HostResults>) + Send + 'static,
    {
        let Ok(c_name) = CString::new(name) else {
            handler(Err(Error::EBADNAME));
            return;
        };
        let c_arg = Box::into_raw(Box::new(handler));
        unsafe {
            c_ares_sys::ares_gethostbyname(
                self.ares_channel,
                c_name.as_ptr(),
                family as i32,
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
                ptr::from_ref(&sockaddr_in).cast()
            }
            SocketAddr::V6(ref v6) => {
                sockaddr_in6 = socket_addrv6_as_sockaddr_in6(v6);
                ptr::from_ref(&sockaddr_in6).cast()
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

    /// Initiate a host query by name and service.
    ///
    /// The `hints` parameter controls the desired address family, socket type, protocol, and
    /// behaviour flags.
    ///
    /// On completion, `handler` is called with the result.
    pub fn get_addrinfo<F>(
        &mut self,
        name: &str,
        service: Option<&str>,
        hints: &AddrInfoHints,
        handler: F,
    ) where
        F: FnOnce(Result<AddrInfoResults>) + Send + 'static,
    {
        let Ok(c_name) = CString::new(name) else {
            handler(Err(Error::EBADNAME));
            return;
        };
        let Ok(c_service) = service.map(CString::new).transpose() else {
            handler(Err(Error::EBADNAME));
            return;
        };
        let c_hints: c_ares_sys::ares_addrinfo_hints = hints.into();
        let c_arg = Box::into_raw(Box::new(handler));
        unsafe {
            c_ares_sys::ares_getaddrinfo(
                self.ares_channel,
                c_name.as_ptr(),
                c_service.as_ref().map_or(ptr::null(), |s| s.as_ptr()),
                &c_hints,
                Some(get_addrinfo_callback::<F>),
                c_arg.cast(),
            );
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
            raw_query_callback::<F>,
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
            raw_query_callback::<F>,
            handler
        );
    }

    /// Send a DNS query using a pre-built [`DnsRecord`].
    ///
    /// On completion, `handler` is called with a `Result<DnsRecord>` containing
    /// the parsed response.
    ///
    /// Returns the query ID on success.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use c_ares::*;
    ///
    /// let mut channel = Channel::new().unwrap();
    /// let mut query = DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError).unwrap();
    /// query.query_add("example.com", DnsRecordType::A, DnsCls::IN).unwrap();
    /// channel.send_dnsrec(&query, move |result| {
    ///     let record = result.unwrap();
    ///     for rr in record.rrs(DnsSection::Answer) {
    ///         if let Some(addr) = rr.get_addr(DnsRrKey::A_ADDR) {
    ///             println!("address: {addr}");
    ///         }
    ///     }
    /// }).unwrap();
    /// // ... drive the event loop ...
    /// ```
    #[cfg(cares1_28)]
    pub fn send_dnsrec<F>(&mut self, dnsrec: &DnsRecord, handler: F) -> Result<u16>
    where
        F: FnOnce(Result<&DnsRecord>) + Send + 'static,
    {
        let mut qid: u16 = 0;
        let c_arg = Box::into_raw(Box::new(handler));
        let status = unsafe {
            c_ares_sys::ares_send_dnsrec(
                self.ares_channel,
                dnsrec.as_raw(),
                Some(dnsrec_callback::<F>),
                c_arg.cast(),
                &mut qid,
            )
        };
        panic::propagate();

        status_to_result(status)?;
        Ok(qid)
    }

    /// Initiate a DNS query for `name` with the given class and type, receiving
    /// a parsed [`DnsRecord`] in the callback.
    ///
    /// Returns the query ID on success.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use c_ares::{Channel, DnsCls, DnsRecordType, DnsRrKey, DnsSection};
    ///
    /// let mut channel = Channel::new().unwrap();
    /// channel.query_dnsrec(
    ///     "example.com",
    ///     DnsCls::IN,
    ///     DnsRecordType::A,
    ///     move |result| {
    ///         let record = result.unwrap();
    ///         for rr in record.rrs(DnsSection::Answer) {
    ///             if let Some(addr) = rr.get_addr(DnsRrKey::A_ADDR) {
    ///                 println!("address: {addr}");
    ///             }
    ///         }
    ///     },
    /// ).unwrap();
    /// // ... drive the event loop with channel.sockets() / channel.process_fd() ...
    /// ```
    #[cfg(cares1_28)]
    pub fn query_dnsrec<F>(
        &mut self,
        name: &str,
        dns_class: DnsCls,
        query_type: DnsRecordType,
        handler: F,
    ) -> Result<u16>
    where
        F: FnOnce(Result<&DnsRecord>) + Send + 'static,
    {
        let c_name = CString::new(name).map_err(|_| Error::EBADNAME)?;
        let mut qid: u16 = 0;
        let c_arg = Box::into_raw(Box::new(handler));
        let status = unsafe {
            c_ares_sys::ares_query_dnsrec(
                self.ares_channel,
                c_name.as_ptr(),
                dns_class.into(),
                query_type.into(),
                Some(dnsrec_callback::<F>),
                c_arg.cast(),
                &mut qid,
            )
        };
        panic::propagate();

        status_to_result(status)?;
        Ok(qid)
    }

    /// Initiate a series of DNS queries using a pre-built [`DnsRecord`],
    /// receiving a parsed [`DnsRecord`] in the callback.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use c_ares::*;
    ///
    /// let mut channel = Channel::new().unwrap();
    /// let mut query = DnsRecord::new(0, DnsFlags::RD, DnsOpcode::Query, DnsRcode::NoError).unwrap();
    /// query.query_add("example.com", DnsRecordType::A, DnsCls::IN).unwrap();
    /// channel.search_dnsrec(&query, move |result| {
    ///     let record = result.unwrap();
    ///     for rr in record.rrs(DnsSection::Answer) {
    ///         if let Some(addr) = rr.get_addr(DnsRrKey::A_ADDR) {
    ///             println!("address: {addr}");
    ///         }
    ///     }
    /// }).unwrap();
    /// // ... drive the event loop ...
    /// ```
    #[cfg(cares1_28)]
    pub fn search_dnsrec<F>(&mut self, dnsrec: &DnsRecord, handler: F) -> Result<()>
    where
        F: FnOnce(Result<&DnsRecord>) + Send + 'static,
    {
        let c_arg = Box::into_raw(Box::new(handler));
        let status = unsafe {
            c_ares_sys::ares_search_dnsrec(
                self.ares_channel,
                dnsrec.as_raw(),
                Some(dnsrec_callback::<F>),
                c_arg.cast(),
            )
        };
        panic::propagate();

        status_to_result(status)
    }

    /// Cancel all requests made on this `Channel`.
    ///
    /// Callbacks will be invoked for each pending query, passing a result
    /// `Err(Error::ECANCELLED)`.
    pub fn cancel(&mut self) {
        unsafe { c_ares_sys::ares_cancel(self.ares_channel) }
        panic::propagate();
    }

    /// Kick c-ares to process a pending write.
    #[cfg(cares1_34)]
    pub fn process_pending_write(&mut self) {
        unsafe { c_ares_sys::ares_process_pending_write(self.ares_channel) }
        panic::propagate();
    }

    /// Return the maximum time to wait before processing timeouts.
    ///
    /// If there are pending queries, returns the time until the next timeout
    /// fires, optionally capped at `max_timeout`. If there are no pending
    /// queries, returns `max_timeout` (which may be `None`).
    pub fn timeout(&self, max_timeout: Option<Duration>) -> Option<Duration> {
        let mut maxtv;
        let maxtv_ptr = match max_timeout {
            Some(d) => {
                maxtv = c_ares_sys::timeval {
                    tv_sec: d.as_secs() as _,
                    tv_usec: d.subsec_micros() as _,
                };
                &mut maxtv
            }
            None => ptr::null_mut(),
        };
        let mut tv = c_ares_sys::timeval {
            tv_sec: 0,
            tv_usec: 0,
        };
        let result = unsafe { c_ares_sys::ares_timeout(self.ares_channel, maxtv_ptr, &mut tv) };
        unsafe { result.as_ref() }
            .map(|tv| Duration::new(tv.tv_sec as u64, (tv.tv_usec as u32) * 1000))
    }

    /// Block until notified that there are no longer any queries in queue, or
    /// the specified timeout has expired.
    ///
    /// Pass `None` to wait indefinitely.
    #[cfg(cares1_27)]
    pub fn queue_wait_empty(&self, timeout: Option<Duration>) -> Result<()> {
        let timeout_ms = match timeout {
            None => -1,
            Some(d) => d.as_millis().try_into().unwrap_or(c_int::MAX),
        };
        let rc = unsafe { c_ares_sys::ares_queue_wait_empty(self.ares_channel, timeout_ms) };
        panic::propagate();
        status_to_result(rc)
    }

    /// Retrieve the total number of active queries pending answers from servers.
    ///
    /// Some c-ares requests may spawn multiple queries, such as
    /// `get_addrinfo()` when using `AddressFamily::UNSPEC`, which will be
    /// reflected in this number.
    #[cfg(cares1_27)]
    pub fn queue_active_queries(&self) -> usize {
        unsafe { c_ares_sys::ares_queue_active_queries(self.ares_channel) }
    }
}

impl Drop for Channel {
    fn drop(&mut self) {
        unsafe { c_ares_sys::ares_destroy(self.ares_channel) }
        {
            let _lock = ARES_LIBRARY_LOCK.lock().unwrap();
            unsafe { c_ares_sys::ares_library_cleanup() }
        }
        if !std::thread::panicking() {
            panic::propagate();
        }
    }
}

unsafe impl Send for Channel {}
unsafe impl Sync for Channel {}

impl fmt::Debug for Channel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Channel").finish_non_exhaustive()
    }
}

unsafe extern "C" fn socket_state_callback<F>(
    data: *mut c_void,
    socket_fd: c_ares_sys::ares_socket_t,
    readable: c_int,
    writable: c_int,
) where
    F: Fn(Socket, bool, bool) + Send + Sync + 'static,
{
    let handler = data.cast::<F>();
    let handler = unsafe { &*handler };
    panic::catch(|| handler(socket_fd, readable != 0, writable != 0));
}

#[cfg(cares1_29)]
unsafe extern "C" fn server_state_callback<F>(
    server_string: *const c_char,
    success: c_ares_sys::ares_bool_t,
    flags: c_int,
    data: *mut c_void,
) where
    F: Fn(&str, bool, ServerStateFlags) + Send + Sync + 'static,
{
    let handler = data.cast::<F>();
    let handler = unsafe { &*handler };
    let server = unsafe { c_string_as_str_unchecked(server_string) };
    panic::catch(|| {
        handler(
            server,
            success != c_ares_sys::ares_bool_t::ARES_FALSE,
            ServerStateFlags::from_bits_truncate(flags),
        )
    });
}

#[cfg(cares1_34)]
unsafe extern "C" fn pending_write_callback<F>(data: *mut c_void)
where
    F: Fn() + Send + Sync + 'static,
{
    let handler = data.cast::<F>();
    let handler = unsafe { &*handler };
    panic::catch(handler);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn channel_new_default() {
        let channel = Channel::new();
        assert!(channel.is_ok());
    }

    #[test]
    fn channel_with_options() {
        let mut options = Options::new();
        options.set_flags(crate::Flags::STAYOPEN).set_tries(2);
        let channel = Channel::with_options(options);
        assert!(channel.is_ok());
    }

    #[test]
    fn channel_set_servers_empty() {
        let mut channel = Channel::new().unwrap();
        let result = channel.set_servers(&[]);
        assert!(result.is_ok());
    }

    #[test]
    fn channel_set_servers_ipv4() {
        let mut channel = Channel::new().unwrap();
        let result = channel.set_servers(&["8.8.8.8", "8.8.4.4"]);
        assert!(result.is_ok());
    }

    #[test]
    fn channel_set_servers_ipv6() {
        let mut channel = Channel::new().unwrap();
        let result = channel.set_servers(&["[2001:4860:4860::8888]"]);
        assert!(result.is_ok());
    }

    #[test]
    fn channel_set_servers_with_port() {
        let mut channel = Channel::new().unwrap();
        let result = channel.set_servers(&["8.8.8.8:53", "[2001:4860:4860::8888]:53"]);
        assert!(result.is_ok());
    }

    #[test]
    fn channel_sockets() {
        let channel = Channel::new().unwrap();
        let sockets = channel.sockets();
        assert_eq!(sockets.iter().count(), 0);
    }

    #[test]
    fn channel_cancel() {
        let mut channel = Channel::new().unwrap();
        channel.cancel();
    }

    #[test]
    fn channel_process_fd_none() {
        let mut channel = Channel::new().unwrap();
        channel.process_fd(None, None);
    }

    #[test]
    fn channel_try_clone() {
        let channel = Channel::new().unwrap();
        let cloned = channel.try_clone();
        assert!(cloned.is_ok());
    }

    #[test]
    fn channel_set_local_ipv4() {
        let mut channel = Channel::new().unwrap();
        channel.set_local_ipv4(Ipv4Addr::new(0, 0, 0, 0));
    }

    #[test]
    fn channel_set_local_ipv6() {
        let mut channel = Channel::new().unwrap();
        channel.set_local_ipv6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0));
    }

    #[test]
    fn channel_set_local_device() {
        let mut channel = Channel::new().unwrap();
        channel.set_local_device("lo").unwrap();
    }

    #[test]
    fn channel_set_sortlist() {
        let mut channel = Channel::new().unwrap();
        let result = channel.set_sortlist(&["130.155.160.0/255.255.240.0", "130.155.0.0"]);
        assert!(result.is_ok());
    }

    #[cfg(cares1_22)]
    #[test]
    fn channel_reinit() {
        let mut channel = Channel::new().unwrap();
        let result = channel.reinit();
        assert!(result.is_ok());
    }

    #[cfg(cares1_24)]
    #[test]
    fn channel_servers() {
        let mut channel = Channel::new().unwrap();
        channel.set_servers(&["8.8.8.8"]).unwrap();
        let servers = channel.servers();
        assert!(!servers.is_empty());
    }

    #[cfg(cares1_24)]
    #[test]
    fn channel_servers_empty() {
        let mut channel = Channel::new().unwrap();
        channel.set_servers(&[]).unwrap();
        let servers = channel.servers();
        assert!(servers.is_empty());
    }

    #[cfg(cares1_34)]
    #[test]
    fn channel_process_fds_empty() {
        use crate::ProcessFlags;
        let mut channel = Channel::new().unwrap();
        let result = channel.process_fds(&[], ProcessFlags::empty());
        assert!(result.is_ok());
    }

    #[cfg(cares1_34)]
    #[test]
    fn channel_process_pending_write() {
        let mut channel = Channel::new().unwrap();
        channel.process_pending_write();
    }

    #[cfg(cares1_28)]
    #[test]
    fn query_dnsrec_rejects_nul_in_name_with_ebadname() {
        let mut channel = Channel::new().unwrap();
        let result = channel.query_dnsrec("ex\0ample.com", DnsCls::IN, DnsRecordType::A, |_| {});
        assert_eq!(result, Err(Error::EBADNAME));
    }

    #[test]
    fn channel_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Channel>();
    }

    #[test]
    fn channel_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Channel>();
    }

    #[test]
    fn channel_fds() {
        use std::mem::MaybeUninit;
        let channel = Channel::new().unwrap();
        unsafe {
            let mut read_fds: c_types::fd_set = MaybeUninit::zeroed().assume_init();
            let mut write_fds: c_types::fd_set = MaybeUninit::zeroed().assume_init();
            let nfds = channel.fds(&mut read_fds, &mut write_fds);
            // No queries started, so should be 0
            assert_eq!(nfds, 0);
        }
    }

    #[test]
    fn set_servers_invalid() {
        let mut channel = Channel::new().unwrap();
        // Invalid server format
        let result = channel.set_servers(&["not-a-valid-ip"]);
        assert!(result.is_err());
    }

    #[test]
    fn set_sortlist_invalid() {
        let mut channel = Channel::new().unwrap();
        // Invalid sortlist format
        let result = channel.set_sortlist(&["not-a-valid-address"]);
        // Should fail
        assert!(result.is_err());
    }

    #[cfg(cares1_29)]
    #[test]
    fn channel_set_server_state_callback() {
        use crate::ServerStateFlags;
        let mut channel = Channel::new().unwrap();
        channel.set_server_state_callback(
            |_server: &str, _success: bool, _flags: ServerStateFlags| {
                // Callback for server state changes
            },
        );
    }

    #[cfg(cares1_34)]
    #[test]
    fn channel_set_pending_write_callback() {
        let mut channel = Channel::new().unwrap();
        channel.set_pending_write_callback(|| {
            // Callback for pending writes
        });
    }

    #[test]
    fn channel_process() {
        use std::mem::MaybeUninit;
        let mut channel = Channel::new().unwrap();
        unsafe {
            let mut read_fds: c_types::fd_set = MaybeUninit::zeroed().assume_init();
            let mut write_fds: c_types::fd_set = MaybeUninit::zeroed().assume_init();
            channel.process(&mut read_fds, &mut write_fds);
        }
    }

    #[cfg(cares1_27)]
    #[test]
    fn channel_queue_active_queries() {
        let channel = Channel::new().unwrap();
        assert_eq!(channel.queue_active_queries(), 0);
    }

    #[cfg(cares1_27)]
    #[test]
    fn channel_queue_wait_empty() {
        let channel = Channel::new().unwrap();
        // No pending queries, should return immediately.
        // Returns ENOTIMP if c-ares was not built with threading support.
        let result = channel.queue_wait_empty(Some(Duration::ZERO));
        assert!(result.is_ok() || result == Err(Error::ENOTIMP));
    }

    #[cfg(cares1_27)]
    #[test]
    fn channel_queue_wait_empty_none_timeout() {
        let channel = Channel::new().unwrap();
        // None means "wait indefinitely", but with no pending queries it returns immediately.
        let result = channel.queue_wait_empty(None);
        assert!(result.is_ok() || result == Err(Error::ENOTIMP));
    }

    #[test]
    fn debug_channel() {
        let channel = Channel::new().unwrap();
        let debug = format!("{:?}", channel);
        assert!(debug.contains("Channel"));
    }

    #[test]
    fn timeout_no_queries_with_max() {
        let channel = Channel::new().unwrap();
        // No pending queries: returns the max_timeout we provide.
        let max = Duration::from_secs(5);
        let result = channel.timeout(Some(max));
        assert_eq!(result, Some(max));
    }

    #[test]
    fn timeout_no_queries_without_max() {
        let channel = Channel::new().unwrap();
        // No pending queries and no max: returns None.
        let result = channel.timeout(None);
        assert_eq!(result, None);
    }
}
