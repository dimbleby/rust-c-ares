// This example uses get_sock() to find out which file descriptors c-ares wants us to listen on,
// and uses epoll() to satisfy those requirements.

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
extern crate nix;

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
mod example {
    extern crate c_ares;
    use nix::sys::epoll::{epoll_create, epoll_ctl, epoll_wait, EpollEvent, EpollFlags, EpollOp};
    use std::collections::HashSet;

    fn print_a_results(result: &c_ares::Result<c_ares::AResults>) {
        match *result {
            Err(ref e) => {
                println!("A lookup failed with error '{}'", e);
            }
            Ok(ref a_results) => {
                println!("Successful A lookup...");
                for a_result in a_results {
                    println!("IPv4: {}", a_result.ipv4());
                    println!("TTL: {}", a_result.ttl());
                }
            }
        }
    }

    fn print_aaaa_results(result: &c_ares::Result<c_ares::AAAAResults>) {
        match *result {
            Err(ref e) => {
                println!("AAAA lookup failed with error '{}'", e);
            }
            Ok(ref aaaa_results) => {
                println!("Successful AAAA lookup...");
                for aaaa_result in aaaa_results {
                    println!("IPv6: {}", aaaa_result.ipv6());
                    println!("TTL: {}", aaaa_result.ttl());
                }
            }
        }
    }

    fn print_caa_results(result: &c_ares::Result<c_ares::CAAResults>) {
        match *result {
            Err(ref e) => {
                println!("CAA lookup failed with error '{}'", e);
            }
            Ok(ref caa_results) => {
                println!("Successful CAA lookup...");
                for caa_result in caa_results {
                    println!(
                        "critical: {}, property: {}, value: {}",
                        caa_result.critical(),
                        caa_result.property().to_string_lossy(),
                        caa_result.value().to_string_lossy()
                    );
                }
            }
        }
    }

    fn print_srv_results(result: &c_ares::Result<c_ares::SRVResults>) {
        match *result {
            Err(ref e) => {
                println!("SRV lookup failed with error '{}'", e);
            }
            Ok(ref srv_results) => {
                println!("Successful SRV lookup...");
                for srv_result in srv_results {
                    println!(
                        "host: {} (port: {}), priority: {}, weight: {}",
                        srv_result.host().to_string_lossy(),
                        srv_result.port(),
                        srv_result.priority(),
                        srv_result.weight()
                    );
                }
            }
        }
    }

    pub fn main() {
        // Create the c_ares::Channel.
        let mut options = c_ares::Options::new();
        options
            .set_flags(c_ares::Flags::STAYOPEN)
            .set_timeout(500)
            .set_tries(3);
        let mut ares_channel =
            c_ares::Channel::with_options(options).expect("Failed to create channel");
        ares_channel
            .set_servers(&["8.8.8.8"])
            .expect("Failed to set servers");

        // Set up some queries.
        ares_channel.query_a("apple.com", move |result| {
            println!();
            print_a_results(&result);
        });

        ares_channel.query_aaaa("microsoft.com", move |result| {
            println!();
            print_aaaa_results(&result);
        });

        ares_channel.query_caa("google.com", move |result| {
            println!();
            print_caa_results(&result);
        });

        ares_channel.query_srv("_xmpp-server._tcp.jabber.org", move |result| {
            println!();
            print_srv_results(&result);
        });

        // Create an epoll file descriptor so that we can listen for events.
        let epoll = epoll_create().expect("Failed to create epoll");
        let mut tracked_fds = HashSet::<c_ares::Socket>::new();
        loop {
            // Ask c-ares what file descriptors we should be listening on, and map those requests
            // onto the epoll file descriptor.
            let mut new_tracked_fds = HashSet::new();
            for (fd, readable, writable) in &ares_channel.get_sock() {
                let mut interest = EpollFlags::empty();
                if readable {
                    interest |= EpollFlags::EPOLLIN;
                }
                if writable {
                    interest |= EpollFlags::EPOLLOUT;
                }
                let mut event = EpollEvent::new(interest, fd as u64);

                // Anything left over in tracked_fds when we exit the loop is no longer wanted by
                // c-ares.
                let op = if tracked_fds.remove(&fd) {
                    EpollOp::EpollCtlMod
                } else {
                    EpollOp::EpollCtlAdd
                };
                new_tracked_fds.insert(fd);

                epoll_ctl(epoll, op, fd, &mut event).expect("epoll_ctl failed");
            }

            // Stop listening for events on file descriptors that c-ares doesn't care about.
            for fd in &tracked_fds {
                epoll_ctl(epoll, EpollOp::EpollCtlDel, *fd, None).expect("epoll_ctl failed");
            }
            tracked_fds = new_tracked_fds;

            // If c-ares isn't asking us to do anything, we're done.
            if tracked_fds.is_empty() {
                break;
            }

            // Wait for something to happen.
            let empty_event = EpollEvent::new(EpollFlags::empty(), 0);
            let mut events = [empty_event; 2];
            let results = epoll_wait(epoll, &mut events, 500).expect("epoll_wait failed");

            // Process whatever happened.
            match results {
                0 => {
                    // No events - must be a timeout.  Tell c-ares about it.
                    ares_channel.process_fd(c_ares::SOCKET_BAD, c_ares::SOCKET_BAD);
                }
                n => {
                    // Sockets became readable or writable.  Tell c-ares.
                    for event in &events[0..n] {
                        let active_fd = event.data() as c_ares::Socket;
                        let rfd = if (event.events() & EpollFlags::EPOLLIN).is_empty() {
                            c_ares::SOCKET_BAD
                        } else {
                            active_fd
                        };
                        let wfd = if (event.events() & EpollFlags::EPOLLOUT).is_empty() {
                            c_ares::SOCKET_BAD
                        } else {
                            active_fd
                        };
                        ares_channel.process_fd(rfd, wfd);
                    }
                }
            }
        }
    }
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
pub fn main() {
    example::main();
}

#[cfg(not(all(unix, any(target_os = "linux", target_os = "android"))))]
pub fn main() {
    println!("this example is not supported on this platform");
}
