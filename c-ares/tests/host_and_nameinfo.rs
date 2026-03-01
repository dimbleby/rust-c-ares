//! Host lookup and name info integration tests.

#![cfg(all(unix, any(target_os = "linux", target_os = "android")))]

mod common;

use c_ares::*;
use common::process_channel;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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
