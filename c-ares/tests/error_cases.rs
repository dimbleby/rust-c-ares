//! Error path and nonexistent domain integration tests.

#![cfg(all(unix, any(target_os = "linux", target_os = "android")))]

mod common;

use c_ares::*;
use common::process_channel;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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
fn get_host_by_name_null_byte() {
    let mut channel = Channel::new().expect("Failed to create channel");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.get_host_by_name("bad\0name", AddressFamily::INET, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        assert_eq!(result.unwrap_err(), Error::EBADNAME);
    });

    assert!(completed.load(Ordering::SeqCst), "Handler was not called");
}

#[test]
fn query_a_null_byte() {
    let mut channel = Channel::new().expect("Failed to create channel");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_a("bad\0name", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        assert_eq!(result.unwrap_err(), Error::EBADNAME);
    });

    assert!(completed.load(Ordering::SeqCst), "Handler was not called");
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
