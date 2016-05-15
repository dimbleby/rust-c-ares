extern crate c_ares_sys;

bitflags!(
    /// Flags that may be provided on a call to `get_name_info()`.
    pub flags NIFlags: i32 {
        /// Only the nodename portion of the FQDN is returned for local hosts.
        const NOFQDN = c_ares_sys::ARES_NI_NOFQDN,

        /// The numeric form of the hostname is returned rather than the name.
        const NUMERICHOST = c_ares_sys::ARES_NI_NUMERICHOST,

        /// An error is returned if the hostname cannot be found in the DNS.
        const NAMEREQD = c_ares_sys::ARES_NI_NAMEREQD,

        /// The numeric form of the service is returned rather than the name.
        const NUMERICSERV = c_ares_sys::ARES_NI_NUMERICSERV,

        /// The service name is to be looked up for the TCP protocol.
        const TCP = c_ares_sys::ARES_NI_TCP,

        /// The service name is to be looked up for the UDP protocol.
        const UDP = c_ares_sys::ARES_NI_UDP,

        /// The service name is to be looked up for the SCTP protocol.
        const SCTP = c_ares_sys::ARES_NI_SCTP,

        /// The service name is to be looked up for the DCCP protocol.
        const DCCP = c_ares_sys::ARES_NI_DCCP,

        /// The numeric form of the scope ID is returned rather than the name.
        const NUMERICSCOPE = c_ares_sys::ARES_NI_NUMERICSCOPE,

        /// A hostname lookup is being requested.
        const LOOKUPHOST = c_ares_sys::ARES_NI_LOOKUPHOST,

        /// A service name lookup is being requested.
        const LOOKUPSERVICE = c_ares_sys::ARES_NI_LOOKUPSERVICE,
    }
);
