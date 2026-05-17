use crate::types::Socket;

/// Information about the set of sockets that `c-ares` is interested in, as returned by
/// `sockets()`.
#[derive(Clone, Copy, Debug)]
pub struct Sockets {
    sockets: [c_ares_sys::ares_socket_t; c_ares_sys::ARES_GETSOCK_MAXNUM],
    bitmask: u32,
}

impl Sockets {
    pub(super) fn new(
        socks: [c_ares_sys::ares_socket_t; c_ares_sys::ARES_GETSOCK_MAXNUM],
        bitmask: u32,
    ) -> Self {
        Sockets {
            sockets: socks,
            bitmask,
        }
    }

    /// Returns an iterator over the sockets that `c-ares` is interested in.
    pub fn iter(&self) -> SocketsIter<'_> {
        SocketsIter {
            next: 0,
            sockets: self,
        }
    }
}

/// Iterator for sockets of interest to `c-ares`.
///
/// Iterator items are `(socket, readable, writable)`.
#[derive(Clone, Debug)]
pub struct SocketsIter<'a> {
    next: usize,
    sockets: &'a Sockets,
}

impl Iterator for SocketsIter<'_> {
    type Item = (Socket, bool, bool);
    fn next(&mut self) -> Option<Self::Item> {
        let index = self.next;
        self.next += 1;
        if index >= c_ares_sys::ARES_GETSOCK_MAXNUM {
            None
        } else {
            let bit = 1 << index;
            let readable = (self.sockets.bitmask & bit) != 0;
            let bit = bit << c_ares_sys::ARES_GETSOCK_MAXNUM;
            let writable = (self.sockets.bitmask & bit) != 0;
            if readable || writable {
                let fd = self.sockets.sockets[index];
                Some((fd, readable, writable))
            } else {
                None
            }
        }
    }
}

impl<'a> IntoIterator for &'a Sockets {
    type Item = (Socket, bool, bool);
    type IntoIter = SocketsIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::super::Channel;
    use super::*;

    #[test]
    fn sockets_iter_empty() {
        let channel = Channel::new().unwrap();
        let sockets = channel.sockets();
        let mut iter = sockets.iter();
        assert!(iter.next().is_none());
    }

    #[test]
    fn sockets_iter_clone() {
        let channel = Channel::new().unwrap();
        let sockets = channel.sockets();
        let iter = sockets.iter();
        let _cloned = iter.clone();
    }

    #[test]
    fn sockets_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<Sockets>();
    }

    #[test]
    fn sockets_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<Sockets>();
    }

    #[test]
    fn sockets_iter_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<SocketsIter<'_>>();
    }

    #[test]
    fn sockets_iter_is_sync() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<SocketsIter<'_>>();
    }

    #[test]
    fn sockets_into_iter() {
        let channel = Channel::new().unwrap();
        let sockets = channel.sockets();
        // Use the IntoIterator implementation - empty channel should have no sockets
        assert_eq!(sockets.into_iter().count(), 0);
    }

    #[test]
    fn sockets_iter_exhausted() {
        // Test that GetSockIter returns None when index >= ARES_GETSOCK_MAXNUM
        let channel = Channel::new().unwrap();
        let sockets = channel.sockets();
        let mut iter = sockets.iter();
        // Exhaust the iterator
        while iter.next().is_some() {}
        // After exhaustion, should continue returning None
        assert!(iter.next().is_none());
        assert!(iter.next().is_none());
    }

    #[test]
    fn sockets_debug() {
        let channel = Channel::new().unwrap();
        let sockets = channel.sockets();
        let debug_str = format!("{sockets:?}");
        assert!(debug_str.contains("Sockets"));
    }

    #[test]
    fn sockets_iter_debug() {
        let channel = Channel::new().unwrap();
        let sockets = channel.sockets();
        let iter = sockets.iter();
        let debug_str = format!("{iter:?}");
        assert!(debug_str.contains("SocketsIter"));
    }

    #[test]
    #[allow(clippy::clone_on_copy)]
    fn sockets_clone() {
        let channel = Channel::new().unwrap();
        let sockets = channel.sockets();
        let _cloned = sockets.clone();
    }

    #[test]
    fn sockets_copy() {
        let channel = Channel::new().unwrap();
        let sockets = channel.sockets();
        let copied: Sockets = sockets;
        let _ = copied;
    }
}
