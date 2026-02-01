//! DNS query integration tests.
//!
//! These tests require network access and are marked #[ignore].
//! Run with: cargo test -- --ignored

#![cfg(all(unix, any(target_os = "linux", target_os = "android")))]

use c_ares::*;
use nix::sys::select::{FdSet, select};
use nix::sys::time::TimeVal;
use std::os::fd::BorrowedFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

/// Helper function to process DNS queries using select.
fn process_channel(channel: &mut Channel, timeout: Duration) {
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

#[test]
#[ignore = "requires network"]
fn query_a_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8", "8.8.4.4"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_a("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");
        assert!(results.iter().count() > 0, "No A records returned");
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_aaaa_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_aaaa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");
        assert!(results.iter().count() > 0, "No AAAA records returned");
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_mx_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_mx("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");
        assert!(
            results.iter().any(|mx| !mx.host().is_empty()),
            "No MX records with host returned"
        );
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_ns_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_ns("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");
        assert!(!results.hostname().is_empty(), "No NS hostname returned");
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_txt_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_txt("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");
        assert!(
            results.iter().any(|txt| !txt.text().is_empty()),
            "No TXT records with text returned"
        );
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_soa_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_soa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let soa = result.expect("Query failed");
        assert!(!soa.name_server().is_empty(), "No SOA name server returned");
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_nonexistent_domain() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_a("this-domain-does-not-exist-12345.invalid", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        assert_eq!(result.unwrap_err(), Error::ENOTFOUND);
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn multiple_concurrent_queries() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let a_completed = Arc::new(AtomicBool::new(false));
    let a_completed_clone = a_completed.clone();
    let aaaa_completed = Arc::new(AtomicBool::new(false));
    let aaaa_completed_clone = aaaa_completed.clone();
    let mx_completed = Arc::new(AtomicBool::new(false));
    let mx_completed_clone = mx_completed.clone();

    channel.query_a("google.com", move |_result| {
        a_completed_clone.store(true, Ordering::SeqCst);
    });

    channel.query_aaaa("google.com", move |_result| {
        aaaa_completed_clone.store(true, Ordering::SeqCst);
    });

    channel.query_mx("google.com", move |_result| {
        mx_completed_clone.store(true, Ordering::SeqCst);
    });

    process_channel(&mut channel, Duration::from_secs(15));

    assert!(
        a_completed.load(Ordering::SeqCst),
        "A query did not complete"
    );
    assert!(
        aaaa_completed.load(Ordering::SeqCst),
        "AAAA query did not complete"
    );
    assert!(
        mx_completed.load(Ordering::SeqCst),
        "MX query did not complete"
    );
}

#[test]
#[ignore = "requires network"]
fn query_cancel() {
    let mut options = Options::new();
    options.set_timeout(5000).set_tries(3);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let cancelled = Arc::new(AtomicBool::new(false));
    let cancelled_clone = cancelled.clone();

    channel.query_a("google.com", move |result| {
        if let Err(Error::ECANCELLED) = result {
            cancelled_clone.store(true, Ordering::SeqCst);
        }
    });

    // Cancel immediately before processing
    channel.cancel();

    // Process should complete quickly since query was cancelled
    process_channel(&mut channel, Duration::from_secs(1));

    assert!(
        cancelled.load(Ordering::SeqCst),
        "Query should have been cancelled"
    );
}

#[test]
#[ignore = "requires network"]
fn query_srv_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    // Query a well-known SRV record
    channel.query_srv("_imaps._tcp.gmail.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");
        assert!(
            results
                .iter()
                .any(|srv| !srv.host().is_empty() && srv.port() > 0),
            "No SRV records with host and port returned"
        );
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_cname_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_cname("www.github.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");
        assert!(!results.hostname().is_empty(), "No CNAME hostname returned");
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_ptr_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_ptr("8.8.8.8.in-addr.arpa", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");
        assert!(!results.hostname().is_empty(), "No PTR hostname returned");
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_caa_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_caa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");
        assert!(
            results.iter().any(|caa| !caa.property().is_empty()),
            "No CAA records with property returned"
        );
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_naptr_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_naptr("sip2sip.info", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");
        assert!(results.iter().count() > 0, "No NAPTR records returned");
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_a_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2).set_domains(&["com"]);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_a("google", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Search failed");
        assert!(results.iter().count() > 0, "No A records returned");
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_aaaa_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_aaaa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_caa_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_caa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_cname_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_cname("www.google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_mx_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_mx("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_naptr_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_naptr("sip2sip.info", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_ns_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_ns("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_ptr_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_ptr("8.8.8.8.in-addr.arpa", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_soa_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_soa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_srv_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_srv("_xmpp-server._tcp.jabber.org", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_txt_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_txt("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn a_result_accessors() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_a("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");

        // Test Display trait
        let _display = format!("{}", results);

        let mut ipv4_valid = false;
        let mut ttl_valid = false;
        for a_result in &results {
            // Test ipv4() accessor
            if !a_result.ipv4().is_unspecified() {
                ipv4_valid = true;
            }
            // Test ttl() accessor
            if a_result.ttl() >= 0 {
                ttl_valid = true;
            }
            // Test Display trait on individual result
            let _display = format!("{}", a_result);
        }
        assert!(ipv4_valid, "No valid IPv4 address");
        assert!(ttl_valid, "No valid TTL");
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn aaaa_result_accessors() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_aaaa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");

        // Test Display trait
        let _display = format!("{}", results);

        let mut ipv6_valid = false;
        for aaaa_result in &results {
            // Test ipv6() accessor
            if !aaaa_result.ipv6().is_unspecified() {
                ipv6_valid = true;
            }
            // Test ttl() accessor
            let _ttl = aaaa_result.ttl();
            // Test Display trait
            let _display = format!("{}", aaaa_result);
        }
        assert!(ipv6_valid, "No valid IPv6 address");
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn mx_result_accessors() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_mx("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");

        // Test Display trait
        let _display = format!("{}", results);

        for mx_result in &results {
            // Test host() and priority() accessors
            let _host = mx_result.host();
            let _priority = mx_result.priority();
            // Test Display trait
            let _display = format!("{}", mx_result);
        }
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn srv_result_accessors() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_srv("_imaps._tcp.gmail.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");

        // Test Display trait
        let _display = format!("{}", results);

        for srv_result in &results {
            // Test all accessors
            let _host = srv_result.host();
            let _port = srv_result.port();
            let _priority = srv_result.priority();
            let _weight = srv_result.weight();
            // Test Display trait
            let _display = format!("{}", srv_result);
        }
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn soa_result_accessors() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_soa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let soa = result.expect("Query failed");

        // Test all accessors
        let _ns = soa.name_server();
        let _hostmaster = soa.hostmaster();
        let _serial = soa.serial();
        let _refresh = soa.refresh();
        let _retry = soa.retry();
        let _expire = soa.expire();
        let _min_ttl = soa.min_ttl();

        // Test Display trait
        let _display = format!("{}", soa);
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn txt_result_accessors() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_txt("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");

        // Test Display trait
        let _display = format!("{}", results);

        for txt_result in &results {
            // Test accessors
            let _record_start = txt_result.record_start();
            let _text = txt_result.text();
            // Test Display trait
            let _display = format!("{}", txt_result);
        }
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_host_by_name_ipv4() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.get_host_by_name("google.com", AddressFamily::INET, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let host_results = result.expect("Query failed");

        // Test hostname accessor
        assert!(!host_results.hostname().is_empty(), "No hostname returned");
        // Test addresses iterator
        for _addr in host_results.addresses() {}
        // Test aliases iterator
        for _alias in host_results.aliases() {}
        // Test Display trait
        let _display = format!("{}", host_results);
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_host_by_name_ipv6() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.get_host_by_name("google.com", AddressFamily::INET6, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let host_results = result.expect("Query failed");
        let _hostname = host_results.hostname();
        for _addr in host_results.addresses() {}
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_host_by_address_ipv4() {
    use std::net::IpAddr;

    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let addr: IpAddr = "8.8.8.8".parse().unwrap();
    channel.get_host_by_address(&addr, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let host_results = result.expect("Query failed");
        assert!(!host_results.hostname().is_empty(), "No hostname returned");
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_host_by_address_ipv6() {
    use std::net::IpAddr;

    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let addr: IpAddr = "2001:4860:4860::8888".parse().unwrap();
    channel.get_host_by_address(&addr, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let host_results = result.expect("Query failed");
        let _hostname = host_results.hostname();
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_name_info_ipv4() {
    use std::net::SocketAddr;

    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
    channel.get_name_info(
        &addr,
        NIFlags::LOOKUPHOST | NIFlags::LOOKUPSERVICE,
        move |result| {
            completed_clone.store(true, Ordering::SeqCst);
            let name_info = result.expect("Query failed");
            assert!(
                name_info.node().is_some() || name_info.service().is_some(),
                "No name info returned"
            );
            // Test Display trait
            let _display = format!("{}", name_info);
        },
    );

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_name_info_ipv6() {
    use std::net::SocketAddr;

    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let addr: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
    channel.get_name_info(&addr, NIFlags::LOOKUPHOST, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let name_info = result.expect("Query failed");
        let _node = name_info.node();
        let _service = name_info.service();
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn raw_query() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    // DNS class IN = 1, type A = 1
    channel.query("google.com", 1, 1, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let data = result.expect("Query failed");
        assert!(!data.is_empty(), "No data returned");
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn raw_search() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2).set_domains(&["com"]);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    // DNS class IN = 1, type A = 1
    channel.search("google", 1, 1, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let data = result.expect("Search failed");
        let _len = data.len();
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_uri_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_uri("_kerberos.fedoraproject.org", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");

        // Test Display trait
        let _display = format!("{}", results);

        for uri_result in &results {
            // Test all accessors
            let _uri = uri_result.uri();
            let _priority = uri_result.priority();
            let _weight = uri_result.weight();
            let _ttl = uri_result.ttl();
            // Test Display trait
            let _display = format!("{}", uri_result);
        }
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn naptr_result_accessors() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_naptr("sip2sip.info", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");

        // Test Display trait
        let _display = format!("{}", results);

        for naptr_result in &results {
            // Test all accessors
            let _flags = naptr_result.flags();
            let _service = naptr_result.service_name();
            let _regexp = naptr_result.reg_exp();
            let _replacement = naptr_result.replacement_pattern();
            let _order = naptr_result.order();
            let _preference = naptr_result.preference();
            // Test Display trait
            let _display = format!("{}", naptr_result);
        }
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn cname_result_accessors() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_cname("www.github.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");

        // Test hostname accessor
        let _hostname = results.hostname();
        // Test aliases iterator
        for _alias in results.aliases() {}
        // Test Display trait
        let _display = format!("{}", results);
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn ptr_result_accessors() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_ptr("8.8.8.8.in-addr.arpa", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");

        // Test hostname accessor
        let _hostname = results.hostname();
        // Test aliases iterator
        for _alias in results.aliases() {}
        // Test Display trait
        let _display = format!("{}", results);
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn ns_result_accessors() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_ns("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");

        // Test hostname accessor
        let _hostname = results.hostname();
        // Test aliases iterator
        for _alias in results.aliases() {}
        // Test Display trait
        let _display = format!("{}", results);
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn caa_result_accessors() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_caa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");

        // Test Display trait
        let _display = format!("{}", results);

        for caa_result in &results {
            // Test all accessors
            let _critical = caa_result.critical();
            let _property = caa_result.property();
            let _value = caa_result.value();
            // Test Display trait
            let _display = format!("{}", caa_result);
        }
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

// ============================================================================
// Server state callback test (cares1_29+)
// ============================================================================

#[cfg(cares1_29)]
#[test]
#[ignore = "requires network"]
fn server_state_callback_invoked() {
    use std::sync::atomic::AtomicUsize;

    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let callback_count = Arc::new(AtomicUsize::new(0));
    let callback_count_clone = callback_count.clone();

    channel.set_server_state_callback(
        move |server: &str, success: bool, flags: ServerStateFlags| {
            callback_count_clone.fetch_add(1, Ordering::SeqCst);
            // Verify callback receives valid data
            assert!(!server.is_empty(), "Server should not be empty");
            // flags should contain UDP or TCP
            let has_transport =
                flags.contains(ServerStateFlags::UDP) || flags.contains(ServerStateFlags::TCP);
            assert!(
                has_transport || flags.is_empty(),
                "Flags should indicate transport"
            );
            let _ = success; // success can be true or false
        },
    );

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_a("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(
        callback_count.load(Ordering::SeqCst) > 0,
        "Server state callback should be invoked"
    );
}

// ============================================================================
// Pending write callback test (cares1_34+)
// ============================================================================

#[cfg(cares1_34)]
#[test]
#[ignore = "requires network"]
fn pending_write_callback_setup() {
    use std::sync::atomic::AtomicUsize;

    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let callback_count = Arc::new(AtomicUsize::new(0));
    let callback_count_clone = callback_count.clone();

    // Set the pending write callback - it may or may not be called depending on
    // whether there's pending data
    channel.set_pending_write_callback(move || {
        callback_count_clone.fetch_add(1, Ordering::SeqCst);
    });

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_a("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    // Note: The callback may or may not be invoked - we just test that setting it works
}

// ============================================================================
// Error path tests for host lookups
// ============================================================================

#[test]
#[ignore = "requires network"]
fn get_host_by_name_nonexistent() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.get_host_by_name(
        "this-domain-does-not-exist-12345.invalid",
        AddressFamily::INET,
        move |result| {
            completed_clone.store(true, Ordering::SeqCst);
            assert_eq!(result.unwrap_err(), Error::ENOTFOUND);
        },
    );

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_host_by_address_nonexistent() {
    use std::net::IpAddr;

    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    // Use a reserved IP that won't have reverse DNS
    let addr: IpAddr = "192.0.2.1".parse().unwrap(); // TEST-NET-1, no reverse DNS

    channel.get_host_by_address(&addr, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        assert_eq!(result.unwrap_err(), Error::ENOTFOUND);
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_name_info_nonexistent() {
    use std::net::SocketAddr;

    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    // Use a reserved IP that won't have reverse DNS
    // NAMEREQD flag requires a name to be found (no numeric fallback)
    let addr: SocketAddr = "192.0.2.1:12345".parse().unwrap();
    channel.get_name_info(
        &addr,
        NIFlags::LOOKUPHOST | NIFlags::NAMEREQD,
        move |result| {
            completed_clone.store(true, Ordering::SeqCst);
            assert_eq!(result.unwrap_err(), Error::ENOTFOUND);
        },
    );

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

// ============================================================================
// Query callback error path tests
// ============================================================================

#[test]
#[ignore = "requires network"]
fn query_cname_nonexistent() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_cname("this-domain-does-not-exist-12345.invalid", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        assert_eq!(result.unwrap_err(), Error::ENOTFOUND);
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_mx_nonexistent() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_mx("this-domain-does-not-exist-12345.invalid", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        assert_eq!(result.unwrap_err(), Error::ENOTFOUND);
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_ns_nonexistent() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_ns("this-domain-does-not-exist-12345.invalid", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        assert_eq!(result.unwrap_err(), Error::ENOTFOUND);
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_txt_nonexistent() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_txt("this-domain-does-not-exist-12345.invalid", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        assert_eq!(result.unwrap_err(), Error::ENOTFOUND);
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_soa_nonexistent() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_soa("this-domain-does-not-exist-12345.invalid", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        assert_eq!(result.unwrap_err(), Error::ENOTFOUND);
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_srv_nonexistent() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_srv(
        "_sip._tcp.this-domain-does-not-exist-12345.invalid",
        move |result| {
            completed_clone.store(true, Ordering::SeqCst);
            assert_eq!(result.unwrap_err(), Error::ENOTFOUND);
        },
    );

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn query_caa_nonexistent() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_caa("this-domain-does-not-exist-12345.invalid", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        assert_eq!(result.unwrap_err(), Error::ENOTFOUND);
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}
