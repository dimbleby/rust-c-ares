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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty() {
        let flags = ServerStateFlags::empty();
        assert!(flags.is_empty());
    }

    #[test]
    fn single() {
        let flags = ServerStateFlags::UDP;
        assert!(flags.contains(ServerStateFlags::UDP));
        assert!(!flags.contains(ServerStateFlags::TCP));
    }

    #[test]
    fn combine() {
        let flags = ServerStateFlags::UDP | ServerStateFlags::TCP;
        assert!(flags.contains(ServerStateFlags::UDP));
        assert!(flags.contains(ServerStateFlags::TCP));
    }

    #[test]
    fn debug() {
        let flags = ServerStateFlags::TCP;
        let debug = format!("{:?}", flags);
        assert!(!debug.is_empty());
    }
}
