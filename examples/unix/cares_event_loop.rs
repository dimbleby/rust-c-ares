// This example uses a mio event loop to poll for readiness.
extern crate c_ares;
extern crate mio;

use std::collections::HashSet;
use std::error::Error;
use std::net::IpAddr;
use std::time::Duration;

fn print_host_results(result: c_ares::Result<c_ares::HostResults>) {
    match result {
        Err(e) => {
            println!("Host lookup failed with error '{}'", e.description());
        }
        Ok(host_results) => {
            println!("Successful host lookup...");
            println!("Hostname: {}", host_results.hostname());
            for alias in host_results.aliases() {
                println!("Alias: {}", alias);
            }
            for address in host_results.addresses() {
                match address {
                    IpAddr::V4(v4) => println!("IPv4: {}", v4),
                    IpAddr::V6(v6) => println!("IPv6: {}", v6),
                }
            }
        }
    }
}

pub fn main() {
    // Create a c_ares::Channel.
    let mut options = c_ares::Options::new();
    options
        .set_flags(c_ares::flags::STAYOPEN | c_ares::flags::EDNS)
        .set_timeout(500)
        .set_tries(3);
    let mut ares_channel = c_ares::Channel::with_options(options)
        .expect("Failed to create channel");
    ares_channel.set_servers(&["8.8.8.8"]).expect("Failed to set servers");

    // Set up some queries.
    ares_channel.get_host_by_name(
        "google.com",
        c_ares::AddressFamily::INET,
        move |result| {
            println!("");
            print_host_results(result);
        }
    );

    let ipv4 = "216.58.212.78".parse::<IpAddr>().unwrap();
    ares_channel.get_host_by_address(&ipv4, move |results| {
        println!("");
        print_host_results(results);
    });

    let ipv6 = "2001:4860:4860::8888".parse::<IpAddr>().unwrap();
    ares_channel.get_host_by_address(&ipv6, move |results| {
        println!("");
        print_host_results(results);
    });

    // Create a poll.
    let poll = mio::Poll::new().expect("Failed to create poll");
    let mut events = mio::Events::with_capacity(16);
    let mut tracked_fds = HashSet::<c_ares::Socket>::new();
    loop {
        // Ask c-ares what file descriptors we should be listening on, and
        // pass that on to the poll.
        let mut new_fds = HashSet::<c_ares::Socket>::new();
        for (fd, readable, writable) in &ares_channel.get_sock() {
            new_fds.insert(fd);
            let efd = mio::unix::EventedFd(&fd);
            let token = mio::Token(fd as usize);
            let mut interest = mio::Ready::empty();
            if readable { interest.insert(mio::Ready::readable()) }
            if writable { interest.insert(mio::Ready::writable()) }
            let register_result = if tracked_fds.contains(&fd) {
                poll.reregister(&efd, token, interest, mio::PollOpt::level())
            } else {
                poll.register(&efd, token, interest, mio::PollOpt::level())
            };
            register_result.expect("failed to register interest");
        }

        // Stop listening for things that we no longer care about.
        let unwanted = &tracked_fds - &new_fds;
        for fd in &unwanted {
            let efd = mio::unix::EventedFd(fd);
            poll.deregister(&efd).expect("failed to deregister interest");
        }
        tracked_fds = new_fds;

        // If we're not waiting for anything, we're done.
        if tracked_fds.is_empty() { break }

        // Wait for something to happen.
        let timeout = Duration::from_millis(100);
        let results = poll.poll(&mut events, Some(timeout))
            .expect("poll failed");

        // Process whatever happened.
        match results {
            0 => {
                // No events - must be a timeout.  Tell c-ares about it.
                ares_channel.process_fd(
                    c_ares::SOCKET_BAD,
                    c_ares::SOCKET_BAD);
            },
            _ => {
                // Sockets became readable or writable.  Tell c-ares.
                for event in &events {
                    let mio::Token(active_fd) = event.token();
                    let rfd = if event.readiness().is_readable() {
                        active_fd as c_ares::Socket
                    } else {
                        c_ares::SOCKET_BAD
                    };
                    let wfd = if event.readiness().is_writable() {
                        active_fd as c_ares::Socket
                    } else {
                        c_ares::SOCKET_BAD
                    };
                    ares_channel.process_fd(rfd, wfd);
                }
            }
        }
    }
}
