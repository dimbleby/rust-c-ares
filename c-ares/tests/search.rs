//! DNS search integration tests.

#![cfg(cares1_28)]

mod common;

use c_ares::*;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[test]
#[ignore = "requires network"]
fn raw_search() {
    assert!(
        c_ares::thread_safety(),
        "c-ares was not built with thread safety"
    );

    let mut options = Options::new();
    options
        .set_flags(Flags::STAYOPEN)
        .set_timeout(Duration::from_millis(2000))
        .set_tries(2)
        .set_domains(["com"])
        .unwrap()
        .set_event_thread(EventSys::Default);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    // DNS class IN = 1, type A = 1
    channel.search("google", 1, 1, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let data = result.expect("Search failed");
        assert!(!data.is_empty(), "No data returned");
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_a_record() {
    assert!(
        c_ares::thread_safety(),
        "c-ares was not built with thread safety"
    );

    let mut options = Options::new();
    options
        .set_flags(Flags::STAYOPEN)
        .set_timeout(Duration::from_millis(2000))
        .set_tries(2)
        .set_domains(["com"])
        .unwrap()
        .set_event_thread(EventSys::Default);
    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(["8.8.8.8"])
        .expect("Failed to set servers");

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_a("google", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Search failed");
        assert!(results.iter().count() > 0, "No A records returned");
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_aaaa_record() {
    let mut channel = common::event_thread_channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_aaaa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        result.expect("Search failed");
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_caa_record() {
    let mut channel = common::event_thread_channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_caa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        result.expect("Search failed");
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_cname_record() {
    let mut channel = common::event_thread_channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_cname("www.github.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        result.expect("Search failed");
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_mx_record() {
    let mut channel = common::event_thread_channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_mx("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        result.expect("Search failed");
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_naptr_record() {
    let mut channel = common::event_thread_channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_naptr("sip2sip.info", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        result.expect("Search failed");
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_ns_record() {
    let mut channel = common::event_thread_channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_ns("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        result.expect("Search failed");
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_ptr_record() {
    let mut channel = common::event_thread_channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_ptr("8.8.8.8.in-addr.arpa", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        result.expect("Search failed");
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_soa_record() {
    let mut channel = common::event_thread_channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_soa("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        result.expect("Search failed");
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_srv_record() {
    let mut channel = common::event_thread_channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_srv("_xmpp-server._tcp.jabber.org", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        result.expect("Search failed");
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}

#[test]
#[ignore = "requires network"]
fn search_txt_record() {
    let mut channel = common::event_thread_channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.search_txt("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        result.expect("Search failed");
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Search did not complete");
}
