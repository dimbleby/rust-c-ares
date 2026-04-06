//! Host lookup and name info integration tests.

#![cfg(cares1_28)]

mod common;

use c_ares::*;
use common::event_thread_channel;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[test]
#[ignore = "requires network"]
fn get_host_by_address_ipv4() {
    use std::net::IpAddr;

    let mut channel = event_thread_channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let addr: IpAddr = "8.8.8.8".parse().unwrap();
    channel.get_host_by_address(&addr, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let host_results = result.expect("Query failed");
        assert!(!host_results.hostname().is_empty(), "No hostname returned");
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_host_by_address_ipv6() {
    use std::net::IpAddr;

    let mut channel = event_thread_channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let addr: IpAddr = "2001:4860:4860::8888".parse().unwrap();
    channel.get_host_by_address(&addr, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let host_results = result.expect("Query failed");
        assert!(!host_results.hostname().is_empty(), "No hostname returned");
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_host_by_name_ipv4() {
    let mut channel = event_thread_channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.get_host_by_name("google.com", AddressFamily::INET, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let host_results = result.expect("Query failed");

        assert!(!host_results.hostname().is_empty(), "No hostname returned");
        assert!(
            host_results.addresses().count() > 0,
            "No addresses returned"
        );
        assert_eq!(host_results.aliases().count(), 0);
        assert!(!format!("{}", host_results).is_empty());
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_host_by_name_ipv6() {
    let mut channel = event_thread_channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.get_host_by_name("google.com", AddressFamily::INET6, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let host_results = result.expect("Query failed");
        assert!(!host_results.hostname().is_empty(), "No hostname returned");
        assert!(
            host_results.addresses().count() > 0,
            "No addresses returned"
        );
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_name_info_ipv4() {
    use std::net::SocketAddr;

    let mut channel = event_thread_channel();

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
            assert!(!format!("{}", name_info).is_empty());
        },
    );

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_name_info_ipv6() {
    use std::net::SocketAddr;

    let mut channel = event_thread_channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let addr: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
    channel.get_name_info(&addr, NIFlags::LOOKUPHOST, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let name_info = result.expect("Query failed");
        assert!(name_info.node().is_some(), "No name info node returned");
        assert!(name_info.service().is_none(), "Name info service returned");
    });

    channel
        .queue_wait_empty(Some(Duration::from_secs(3)))
        .expect("queue_wait_empty");

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}
