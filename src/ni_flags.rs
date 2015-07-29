#[allow(dead_code)]
extern crate c_ares_sys;

bitflags!(
    #[doc = "Flags that may be provided on a call to `get_name_info()`."]
    flags NIFlags: i32 {
        #[doc = "Only the nodename portion of the FQDN is returned for local"]
        #[doc = "hosts."]
        const NOFQDN = c_ares_sys::ARES_NI_NOFQDN,

        #[doc = "The numeric form of the hostname is returned rather than the"]
        #[doc = "name."]
        const NUMERICHOST = c_ares_sys::ARES_NI_NUMERICHOST,

        #[doc = "An error is returned if the hostname cannot be found in the"]
        #[doc = "DNS."]
        const NAMEREQD = c_ares_sys::ARES_NI_NAMEREQD,

        #[doc = "The numeric form of the service is returned rather than the"]
        #[doc = "name."]
        const NUMERICSERV = c_ares_sys::ARES_NI_NUMERICSERV,

        #[doc = "The service name is to be looked up for the TCP protocol."]
        const TCP = c_ares_sys::ARES_NI_TCP,

        #[doc = "The service name is to be looked up for the UDP protocol."]
        const UDP = c_ares_sys::ARES_NI_UDP,

        #[doc = "The service name is to be looked up for the SCTP protocol."]
        const SCTP = c_ares_sys::ARES_NI_SCTP,

        #[doc = "The service name is to be looked up for the DCCP protocol."]
        const DCCP = c_ares_sys::ARES_NI_DCCP,

        #[doc = "The numeric form of the scope ID is returned rather than"]
        #[doc = "the name."]
        const NUMERICSCOPE = c_ares_sys::ARES_NI_NUMERICSCOPE,

        #[doc = "A hostname lookup is being requested."]
        const LOOKUPHOST = c_ares_sys::ARES_NI_LOOKUPHOST,

        #[doc = "A service name lookup is being requested."]
        const LOOKUPSERVICE = c_ares_sys::ARES_NI_LOOKUPSERVICE,
    }
);
