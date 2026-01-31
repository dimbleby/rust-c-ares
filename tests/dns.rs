//! DNS query integration tests.
//!
//! These tests require network access and are marked #[ignore].
//! Run with: cargo test -- --ignored

#![cfg(all(unix, any(target_os = "linux", target_os = "android")))]

use c_ares::*;
use nix::sys::select::{select, FdSet};
use nix::sys::time::TimeVal;
use std::os::fd::BorrowedFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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

        let result = select(None, Some(&mut read_fds), Some(&mut write_fds), None, Some(&mut tv));

        match result {
            Ok(0) => {
                // Timeout - still call process_fd to handle c-ares timeouts
                channel.process_fd(SOCKET_BAD, SOCKET_BAD);
            }
            Ok(_) => {
                // Process active file descriptors
                for (fd, _, _) in &socks {
                    let borrowed_fd = unsafe { BorrowedFd::borrow_raw(*fd) };
                    let readable = read_fds.contains(borrowed_fd);
                    let writable = write_fds.contains(borrowed_fd);
                    if readable || writable {
                        let rfd = if readable { *fd } else { SOCKET_BAD };
                        let wfd = if writable { *fd } else { SOCKET_BAD };
                        channel.process_fd(rfd, wfd);
                    }
                }
            }
            Err(_) => break,
        }
    }
}

#[test]
#[ignore]
fn query_a_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8", "8.8.4.4"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let success = Arc::new(AtomicBool::new(false));
    let success_clone = success.clone();

    channel.query_a("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(results) = result {
            let count = results.iter().count();
            if count > 0 {
                success_clone.store(true, Ordering::SeqCst);
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(success.load(Ordering::SeqCst), "Query did not return A records");
}

#[test]
#[ignore]
fn query_aaaa_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let success = Arc::new(AtomicBool::new(false));
    let success_clone = success.clone();

    channel.query_aaaa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(results) = result {
            let count = results.iter().count();
            if count > 0 {
                success_clone.store(true, Ordering::SeqCst);
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(
        success.load(Ordering::SeqCst),
        "Query did not return AAAA records"
    );
}

#[test]
#[ignore]
fn query_mx_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let success = Arc::new(AtomicBool::new(false));
    let success_clone = success.clone();

    channel.query_mx("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(results) = result {
            for mx in &results {
                if !mx.host().is_empty() {
                    success_clone.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(
        success.load(Ordering::SeqCst),
        "Query did not return MX records"
    );
}

#[test]
#[ignore]
fn query_ns_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let success = Arc::new(AtomicBool::new(false));
    let success_clone = success.clone();

    channel.query_ns("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(results) = result {
            if !results.hostname().is_empty() {
                success_clone.store(true, Ordering::SeqCst);
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(
        success.load(Ordering::SeqCst),
        "Query did not return NS records"
    );
}

#[test]
#[ignore]
fn query_txt_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let success = Arc::new(AtomicBool::new(false));
    let success_clone = success.clone();

    channel.query_txt("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(results) = result {
            for txt in &results {
                if !txt.text().is_empty() {
                    success_clone.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(
        success.load(Ordering::SeqCst),
        "Query did not return TXT records"
    );
}

#[test]
#[ignore]
fn query_soa_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let success = Arc::new(AtomicBool::new(false));
    let success_clone = success.clone();

    channel.query_soa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(soa) = result {
            if !soa.name_server().is_empty() {
                success_clone.store(true, Ordering::SeqCst);
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(
        success.load(Ordering::SeqCst),
        "Query did not return SOA record"
    );
}

#[test]
#[ignore]
fn query_nonexistent_domain() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let got_error = Arc::new(AtomicBool::new(false));
    let got_error_clone = got_error.clone();

    channel.query_a("this-domain-does-not-exist-12345.invalid", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if result.is_err() {
            got_error_clone.store(true, Ordering::SeqCst);
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(
        got_error.load(Ordering::SeqCst),
        "Query should have returned an error for nonexistent domain"
    );
}

#[test]
#[ignore]
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

    assert!(a_completed.load(Ordering::SeqCst), "A query did not complete");
    assert!(
        aaaa_completed.load(Ordering::SeqCst),
        "AAAA query did not complete"
    );
    assert!(mx_completed.load(Ordering::SeqCst), "MX query did not complete");
}

#[test]
#[ignore]
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
#[ignore]
fn query_srv_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let success = Arc::new(AtomicBool::new(false));
    let success_clone = success.clone();

    // Query a well-known SRV record
    channel.query_srv("_imaps._tcp.gmail.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(results) = result {
            for srv in &results {
                if !srv.host().is_empty() && srv.port() > 0 {
                    success_clone.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(
        success.load(Ordering::SeqCst),
        "Query did not return SRV records"
    );
}

#[test]
#[ignore]
fn query_cname_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let success = Arc::new(AtomicBool::new(false));
    let success_clone = success.clone();

    // www.google.com typically has a CNAME
    channel.query_cname("www.google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(results) = result {
            if !results.hostname().is_empty() {
                success_clone.store(true, Ordering::SeqCst);
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    // Note: CNAME might not always be present, so we just check completion
}

#[test]
#[ignore]
fn query_ptr_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let success = Arc::new(AtomicBool::new(false));
    let success_clone = success.clone();

    // Query reverse DNS for Google's DNS server
    channel.query_ptr("8.8.8.8.in-addr.arpa", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(results) = result {
            if !results.hostname().is_empty() {
                success_clone.store(true, Ordering::SeqCst);
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(
        success.load(Ordering::SeqCst),
        "Query did not return PTR record"
    );
}

#[test]
#[ignore]
fn query_caa_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let success = Arc::new(AtomicBool::new(false));
    let success_clone = success.clone();

    channel.query_caa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(results) = result {
            for caa in &results {
                if !caa.property().is_empty() {
                    success_clone.store(true, Ordering::SeqCst);
                    break;
                }
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    // CAA records might not always be present
}

#[test]
#[ignore]
fn query_naptr_record() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    // sip2sip.info has NAPTR records for SIP services
    channel.query_naptr("sip2sip.info", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(results) = result {
            // Should have NAPTR records
            assert!(results.iter().count() > 0, "Expected NAPTR records");
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
fn search_a_record() {
    let mut options = Options::new();
    options
        .set_timeout(2000)
        .set_tries(2)
        .set_domains(&["com"]);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let success = Arc::new(AtomicBool::new(false));
    let success_clone = success.clone();

    // search_a will try appending search domains
    channel.search_a("google", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(results) = result {
            if results.iter().count() > 0 {
                success_clone.store(true, Ordering::SeqCst);
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore]
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

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore]
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

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore]
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

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore]
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

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore]
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

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore]
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

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore]
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

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore]
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

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore]
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

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore]
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

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore]
fn a_result_accessors() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let ipv4_valid = Arc::new(AtomicBool::new(false));
    let ipv4_valid_clone = ipv4_valid.clone();
    let ttl_valid = Arc::new(AtomicBool::new(false));
    let ttl_valid_clone = ttl_valid.clone();

    channel.query_a("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(results) = result {
            // Test Display trait
            let _display = format!("{}", results);

            for a_result in &results {
                // Test ipv4() accessor
                let ipv4 = a_result.ipv4();
                if !ipv4.is_unspecified() {
                    ipv4_valid_clone.store(true, Ordering::SeqCst);
                }

                // Test ttl() accessor
                let ttl = a_result.ttl();
                if ttl >= 0 {
                    ttl_valid_clone.store(true, Ordering::SeqCst);
                }

                // Test Display trait on individual result
                let _display = format!("{}", a_result);
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(ipv4_valid.load(Ordering::SeqCst), "No valid IPv4 address");
    assert!(ttl_valid.load(Ordering::SeqCst), "No valid TTL");
}

#[test]
#[ignore]
fn aaaa_result_accessors() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let ipv6_valid = Arc::new(AtomicBool::new(false));
    let ipv6_valid_clone = ipv6_valid.clone();

    channel.query_aaaa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(results) = result {
            // Test Display trait
            let _display = format!("{}", results);

            for aaaa_result in &results {
                // Test ipv6() accessor
                let ipv6 = aaaa_result.ipv6();
                if !ipv6.is_unspecified() {
                    ipv6_valid_clone.store(true, Ordering::SeqCst);
                }

                // Test ttl() accessor
                let _ttl = aaaa_result.ttl();

                // Test Display trait
                let _display = format!("{}", aaaa_result);
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(ipv6_valid.load(Ordering::SeqCst), "No valid IPv6 address");
}

#[test]
#[ignore]
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
        if let Ok(results) = result {
            // Test Display trait
            let _display = format!("{}", results);

            for mx_result in &results {
                // Test host() and priority() accessors
                let _host = mx_result.host();
                let _priority = mx_result.priority();

                // Test Display trait
                let _display = format!("{}", mx_result);
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
        if let Ok(results) = result {
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
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
        if let Ok(soa) = result {
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
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
        if let Ok(results) = result {
            // Test Display trait
            let _display = format!("{}", results);

            for txt_result in &results {
                // Test accessors
                let _record_start = txt_result.record_start();
                let _text = txt_result.text();

                // Test Display trait
                let _display = format!("{}", txt_result);
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
fn get_host_by_name_ipv4() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let success = Arc::new(AtomicBool::new(false));
    let success_clone = success.clone();

    channel.get_host_by_name("google.com", AddressFamily::INET, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(host_results) = result {
            // Test hostname accessor
            if !host_results.hostname().is_empty() {
                success_clone.store(true, Ordering::SeqCst);
            }
            // Test addresses iterator
            for _addr in host_results.addresses() {
                // Just iterate
            }
            // Test aliases iterator
            for _alias in host_results.aliases() {
                // Just iterate
            }
            // Test Display trait
            let _display = format!("{}", host_results);
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(success.load(Ordering::SeqCst), "No hostname returned");
}

#[test]
#[ignore]
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
        if let Ok(host_results) = result {
            let _hostname = host_results.hostname();
            for _addr in host_results.addresses() {}
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
    let success = Arc::new(AtomicBool::new(false));
    let success_clone = success.clone();

    // Reverse lookup for Google's DNS server
    let addr: IpAddr = "8.8.8.8".parse().unwrap();
    channel.get_host_by_address(&addr, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(host_results) = result {
            if !host_results.hostname().is_empty() {
                success_clone.store(true, Ordering::SeqCst);
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(success.load(Ordering::SeqCst), "No hostname returned");
}

#[test]
#[ignore]
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

    // Reverse lookup for Google's IPv6 DNS server
    let addr: IpAddr = "2001:4860:4860::8888".parse().unwrap();
    channel.get_host_by_address(&addr, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(host_results) = result {
            let _hostname = host_results.hostname();
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
    let success = Arc::new(AtomicBool::new(false));
    let success_clone = success.clone();

    let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
    channel.get_name_info(&addr, NIFlags::LOOKUPHOST | NIFlags::LOOKUPSERVICE, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(name_info) = result {
            // Test accessors
            if name_info.node().is_some() || name_info.service().is_some() {
                success_clone.store(true, Ordering::SeqCst);
            }
            // Test Display trait
            let _display = format!("{}", name_info);
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(success.load(Ordering::SeqCst), "No name info returned");
}

#[test]
#[ignore]
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
        if let Ok(name_info) = result {
            let _node = name_info.node();
            let _service = name_info.service();
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
fn raw_query() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let success = Arc::new(AtomicBool::new(false));
    let success_clone = success.clone();

    // DNS class IN = 1, type A = 1
    channel.query("google.com", 1, 1, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if let Ok(data) = result {
            if !data.is_empty() {
                success_clone.store(true, Ordering::SeqCst);
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(success.load(Ordering::SeqCst), "No data returned");
}

#[test]
#[ignore]
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
        if let Ok(data) = result {
            let _len = data.len();
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore]
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
        if let Ok(results) = result {
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
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
        if let Ok(results) = result {
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
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
        if let Ok(results) = result {
            // Test hostname accessor
            let _hostname = results.hostname();

            // Test aliases iterator
            for _alias in results.aliases() {
                // Just iterate
            }

            // Test Display trait
            let _display = format!("{}", results);
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
        if let Ok(results) = result {
            // Test hostname accessor
            let _hostname = results.hostname();

            // Test aliases iterator
            for _alias in results.aliases() {
                // Just iterate
            }

            // Test Display trait
            let _display = format!("{}", results);
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
        if let Ok(results) = result {
            // Test hostname accessor
            let _hostname = results.hostname();

            // Test aliases iterator
            for _alias in results.aliases() {
                // Just iterate
            }

            // Test Display trait
            let _display = format!("{}", results);
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
        if let Ok(results) = result {
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
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

// ============================================================================
// Server state callback test (cares1_29+)
// ============================================================================

#[cfg(cares1_29)]
#[test]
#[ignore]
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

    channel.set_server_state_callback(move |server: &str, success: bool, flags: ServerStateFlags| {
        callback_count_clone.fetch_add(1, Ordering::SeqCst);
        // Verify callback receives valid data
        assert!(!server.is_empty(), "Server should not be empty");
        // flags should contain UDP or TCP
        let has_transport = flags.contains(ServerStateFlags::UDP) || flags.contains(ServerStateFlags::TCP);
        assert!(has_transport || flags.is_empty(), "Flags should indicate transport");
        let _ = success; // success can be true or false
    });

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_a("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(callback_count.load(Ordering::SeqCst) > 0, "Server state callback should be invoked");
}

// ============================================================================
// Pending write callback test (cares1_34+)
// ============================================================================

#[cfg(cares1_34)]
#[test]
#[ignore]
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

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    // Note: The callback may or may not be invoked - we just test that setting it works
}

// ============================================================================
// Error path tests for host lookups
// ============================================================================

#[test]
#[ignore]
fn get_host_by_name_nonexistent() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();
    let got_error = Arc::new(AtomicBool::new(false));
    let got_error_clone = got_error.clone();

    channel.get_host_by_name("this-domain-does-not-exist-12345.invalid", AddressFamily::INET, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        if result.is_err() {
            got_error_clone.store(true, Ordering::SeqCst);
        }
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(got_error.load(Ordering::SeqCst), "Should have returned error for nonexistent domain");
}

#[test]
#[ignore]
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
        // Either success or error is fine - we just want the callback to be called
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
    let addr: SocketAddr = "192.0.2.1:12345".parse().unwrap();
    channel.get_name_info(&addr, NIFlags::LOOKUPHOST, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        // Either success or error is fine
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

// ============================================================================
// Query callback error path tests
// ============================================================================

#[test]
#[ignore]
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
        // Should return error for nonexistent domain
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
fn query_srv_nonexistent() {
    let mut options = Options::new();
    options.set_timeout(2000).set_tries(2);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(&["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_srv("_sip._tcp.this-domain-does-not-exist-12345.invalid", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore]
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
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(10));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}
