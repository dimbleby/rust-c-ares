extern crate c_ares_sys;

use std::os::unix::io;

pub struct GetSock {
    socks: [c_ares_sys::ares_socket_t; c_ares_sys::ARES_GETSOCK_MAXNUM],
    bitmask: u32,
}

impl GetSock {
    pub fn new(
        socks: [c_ares_sys::ares_socket_t; c_ares_sys::ARES_GETSOCK_MAXNUM],
        bitmask: u32) -> GetSock {
        GetSock {
            socks: socks,
            bitmask: bitmask,
        }
    }

    /// Returns an iterator over the sockets that c-ares is interested in.
    ///
    /// Iterator items are (fd, readable, writable).
    pub fn sockets(&self) -> SocketInfoIterator {
        SocketInfoIterator {
            next: 0,
            getsock: self,
        }
    }
}

pub struct SocketInfoIterator<'a> {
    next: usize,
    getsock: &'a GetSock,
}

impl<'a> Iterator for SocketInfoIterator<'a> {
    type Item = (io::RawFd, bool, bool);
    fn next(&mut self) -> Option<Self::Item> {
        let index = self.next;
        if self.next == c_ares_sys::ARES_GETSOCK_MAXNUM {
            None
        } else {
            let fd = self.getsock.socks[index] as io::RawFd;
            let bit = 1 << index;
            let readable = (self.getsock.bitmask & bit) != 0;
            let bit = bit << c_ares_sys::ARES_GETSOCK_MAXNUM;
            let writable = (self.getsock.bitmask & bit) != 0;
            self.next = self.next + 1;

            if readable || writable {
                Some((fd, readable, writable))
            } else {
                None
            }
        }
    }
}
