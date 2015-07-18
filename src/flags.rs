#[allow(dead_code)]
extern crate c_ares_sys;

/// Flags that may be passed when initializing a channel.
bitflags!(
    #[doc = "Flags that may be passed when initializing a channel."]
    flags Flags: i32 {
        #[doc = "Always use TCP queries (the \"virtual circuit\") instead of"]
        #[doc = "UDP queries.  Normally, TCP is only used if a UDP query"]
        #[doc = "yields a truncated result."]
        const USEVC = c_ares_sys::ARES_FLAG_USEVC,

        #[doc = "Only query the first server in the list of servers to"]
        #[doc = "query."]
        const PRIMARY = c_ares_sys::ARES_FLAG_PRIMARY,

        #[doc = "If a truncated response to a UDP query is received, do not"]
        #[doc = "fall back to TCP; simply continue on with the truncated"]
        #[doc = "response."]
        const IGNTC = c_ares_sys::ARES_FLAG_IGNTC,

        #[doc = "Do not set the \"recursion desired\" bit on outgoing"]
        #[doc = "queries, so that the name server being contacted will not"]
        #[doc = "try to fetch the answer from other servers if it doesn't"]
        #[doc = "know the answer locally."]
        const NORECURSE = c_ares_sys::ARES_FLAG_NORECURSE,

        #[doc = "Do not close communications sockets when the number of"]
        #[doc = "active queries drops to zero."]
        const STAYOPEN = c_ares_sys::ARES_FLAG_STAYOPEN,

        #[doc = "Do not use the default search domains; only query hostnames"]
        #[doc = "as-is or as aliases."]
        const NOSEARCH = c_ares_sys::ARES_FLAG_NOSEARCH,

        #[doc = "Do not honor the HOSTALIASES environment variable, which"]
        #[doc = "normally specifies a file of hostname translations."]
        const NOALIASES = c_ares_sys::ARES_FLAG_NOALIASES,

        #[doc = "Do not discard responses with the SERVFAIL, NOTIMP, or"]
        #[doc = "REFUSED response code or responses whose questions don't"]
        #[doc = "match the questions in the request. Primarily useful for"]
        #[doc = "writing clients which might be used to test or debug name"]
        #[doc = "servers."]
        const NOCHECKRESP = c_ares_sys::ARES_FLAG_NOCHECKRESP,

        #[doc = "Use Extension Mechanisms for DNS."]
        const EDNS = c_ares_sys::ARES_FLAG_EDNS,
    }
);
