//! Tests for DNS result accessor methods and Display traits.

#![cfg(all(unix, any(target_os = "linux", target_os = "android")))]

mod common;

use c_ares::*;
use common::process_channel;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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
