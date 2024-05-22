use bitflags::bitflags;
bitflags!(
    /// Flags that may be provided on server state callbacks.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct ServerStateFlags: i32 {
        /// Query used UDP.
        const UDP = c_ares_sys::ARES_SERV_STATE_UDP;

        /// Query used TCP.
        const TCP = c_ares_sys::ARES_SERV_STATE_TCP;
    }
);
