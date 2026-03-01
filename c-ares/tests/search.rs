//! DNS search integration tests.

#![cfg(all(unix, any(target_os = "linux", target_os = "android")))]

mod common;

use c_ares::*;
use common::process_channel;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[test]
#[ignore = "requires network"]
fn raw_search() {
    let mut options = Options::new();
    options
        .set_timeout(2000)
        .set_tries(2)
        .set_domains(&["com"])
        .unwrap();
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
fn search_a_record() {
    let mut options = Options::new();
    options
        .set_timeout(2000)
        .set_tries(2)
        .set_domains(&["com"])
        .unwrap();
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
