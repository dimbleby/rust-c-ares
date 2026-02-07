use c_ares::*;
use nix::sys::select::{FdSet, select};
use nix::sys::time::TimeVal;
use std::os::fd::BorrowedFd;
use std::time::Duration;

/// Helper function to process DNS queries using select.
pub fn process_channel(channel: &mut Channel, timeout: Duration) {
    use std::time::Instant;

    let start = Instant::now();
    loop {
        if start.elapsed() > timeout {
            break;
        }

        let get_sock = channel.get_sock();
        let socks: Vec<_> = get_sock.iter().collect();

        if socks.is_empty() {
            break;
        }

        let mut read_fds = FdSet::new();
        let mut write_fds = FdSet::new();

        for (fd, readable, writable) in &socks {
            let borrowed_fd = unsafe { BorrowedFd::borrow_raw(*fd) };
            if *readable {
                read_fds.insert(borrowed_fd);
            }
            if *writable {
                write_fds.insert(borrowed_fd);
            }
        }

        let mut tv = TimeVal::new(0, 100_000); // 100ms

        let result = select(
            None,
            Some(&mut read_fds),
            Some(&mut write_fds),
            None,
            Some(&mut tv),
        );

        match result {
            Ok(_) => {
                // Process active file descriptors
                let mut called = false;
                for (fd, _, _) in &socks {
                    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(*fd) };
                    let readable = read_fds.contains(borrowed_fd);
                    let writable = write_fds.contains(borrowed_fd);
                    if readable || writable {
                        let rfd = if readable { *fd } else { SOCKET_BAD };
                        let wfd = if writable { *fd } else { SOCKET_BAD };
                        channel.process_fd(rfd, wfd);
                        called = true;
                    }
                }
                // Always call process_fd at least once to handle c-ares timeouts
                if !called {
                    channel.process_fd(SOCKET_BAD, SOCKET_BAD);
                }
            }
            Err(_) => break,
        }
    }
}
