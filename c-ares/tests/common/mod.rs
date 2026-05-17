//! Shared helpers for the `c-ares` integration tests.
//!
//! These tests build a plain `Channel` (no built-in event thread) and drive
//! its I/O manually via `process_channel`. Doing so means the tests work
//! regardless of whether c-ares was compiled with thread-safety support.

use c_ares::*;
use std::time::{Duration, Instant};

/// Create a `Channel` configured to talk to `8.8.8.8`.
///
/// The channel does not use the c-ares built-in event thread; drive its I/O
/// with [`process_channel`].
pub fn channel() -> Channel {
    let mut options = Options::new();
    options
        .set_flags(Flags::STAYOPEN)
        .set_timeout(Duration::from_secs(2))
        .set_tries(2);

    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(["8.8.8.8"])
        .expect("Failed to set servers");
    channel
}

/// Drive `channel`'s I/O until it has no more sockets of interest, or
/// `timeout` elapses.
pub fn process_channel(channel: &mut Channel, timeout: Duration) {
    let start = Instant::now();
    let mut events = polling::Events::new();
    loop {
        if start.elapsed() > timeout {
            break;
        }

        let sockets = channel.sockets();
        let socks: Vec<_> = sockets.iter().collect();
        if socks.is_empty() {
            break;
        }

        // Fresh poller per iteration - cheap and avoids tracking which sockets
        // we've previously registered.
        let poller = polling::Poller::new().expect("create polling::Poller");
        for (sock, readable, writable) in &socks {
            let key = usize::try_from(*sock).expect("socket fits in usize");
            let event = polling::Event::new(key, *readable, *writable);
            // Safety: c-ares is telling us this socket is open.
            unsafe {
                poller.add(*sock, event).expect("poller.add");
            }
        }

        events.clear();
        let _ = poller.wait(&mut events, Some(Duration::from_millis(100)));

        if events.is_empty() {
            // Drive c-ares timeouts.
            channel.process_fd(None, None);
        } else {
            for event in events.iter() {
                let socket = Socket::try_from(event.key).expect("event key is a socket");
                let rfd = event.readable.then_some(socket);
                let wfd = event.writable.then_some(socket);
                channel.process_fd(rfd, wfd);
            }
        }
    }
}
