//! Flags that may be passed when initializing a `Channel`.
extern crate c_ares_sys;

bitflags!(
    /// Flags that may be passed when initializing a `Channel`.
    pub flags Flags: i32 {
        /// Always use TCP queries (the "virtual circuit") instead of UDP
        /// queries.  Normally, TCP is only used if a UDP query yields a
        /// truncated result.
        const USEVC = c_ares_sys::ARES_FLAG_USEVC,

        /// Only query the first server in the list of servers to query.
        const PRIMARY = c_ares_sys::ARES_FLAG_PRIMARY,

        /// If a truncated response to a UDP query is received, do not fall
        /// back to TCP; simply continue on with the truncated response.
        const IGNTC = c_ares_sys::ARES_FLAG_IGNTC,

        /// Do not set the "recursion desired" bit on outgoing queries, so
        /// that the name server being contacted will not try to fetch the
        /// answer from other servers if it doesn't know the answer locally.
        const NORECURSE = c_ares_sys::ARES_FLAG_NORECURSE,

        /// Do not close communications sockets when the number of active
        /// queries drops to zero.
        const STAYOPEN = c_ares_sys::ARES_FLAG_STAYOPEN,

        /// Do not use the default search domains; only query hostnames as-is
        /// or as aliases.
        const NOSEARCH = c_ares_sys::ARES_FLAG_NOSEARCH,

        /// Do not honor the HOSTALIASES environment variable, which normally
        /// specifies a file of hostname translations.
        const NOALIASES = c_ares_sys::ARES_FLAG_NOALIASES,

        /// Do not discard responses with the SERVFAIL, NOTIMP, or REFUSED
        /// response code or responses whose questions don't match the
        /// questions in the request. Primarily useful for writing clients
        /// which might be used to test or debug name servers.
        const NOCHECKRESP = c_ares_sys::ARES_FLAG_NOCHECKRESP,

        /// Use Extension Mechanisms for DNS.
        const EDNS = c_ares_sys::ARES_FLAG_EDNS,
    }
);
