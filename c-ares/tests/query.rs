//! DNS query integration tests for specific record types, including result accessor methods and
//! Display traits.

#![cfg(all(unix, any(target_os = "linux", target_os = "android")))]

mod common;

use c_ares::*;
use common::process_channel;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

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

        let _display = format!("{}", results);

        let mut ipv4_valid = false;
        let mut ttl_valid = false;
        for a_result in &results {
            if !a_result.ipv4().is_unspecified() {
                ipv4_valid = true;
            }
            if a_result.ttl() >= 0 {
                ttl_valid = true;
            }
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

        let _display = format!("{}", results);

        let mut ipv6_valid = false;
        for aaaa_result in &results {
            if !aaaa_result.ipv6().is_unspecified() {
                ipv6_valid = true;
            }
            let _ttl = aaaa_result.ttl();
            let _display = format!("{}", aaaa_result);
        }
        assert!(ipv6_valid, "No valid IPv6 address");
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

        let _display = format!("{}", results);

        for caa_result in &results {
            let _critical = caa_result.critical();
            let _property = caa_result.property();
            let _value = caa_result.value();
            let _display = format!("{}", caa_result);
        }
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

        for _alias in results.aliases() {}
        let _display = format!("{}", results);
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

        let _display = format!("{}", results);

        for mx_result in &results {
            let _host = mx_result.host();
            let _priority = mx_result.priority();
            let _display = format!("{}", mx_result);
        }
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

        let _display = format!("{}", results);

        for naptr_result in &results {
            let _flags = naptr_result.flags();
            let _service = naptr_result.service_name();
            let _regexp = naptr_result.reg_exp();
            let _replacement = naptr_result.replacement_pattern();
            let _order = naptr_result.order();
            let _preference = naptr_result.preference();
            let _display = format!("{}", naptr_result);
        }
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

        for _alias in results.aliases() {}
        let _display = format!("{}", results);
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

        for _alias in results.aliases() {}
        let _display = format!("{}", results);
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

        let _hostmaster = soa.hostmaster();
        let _serial = soa.serial();
        let _refresh = soa.refresh();
        let _retry = soa.retry();
        let _expire = soa.expire();
        let _min_ttl = soa.min_ttl();
        let _display = format!("{}", soa);
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
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

    channel.query_srv("_imaps._tcp.gmail.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let results = result.expect("Query failed");
        assert!(
            results
                .iter()
                .any(|srv| !srv.host().is_empty() && srv.port() > 0),
            "No SRV records with host and port returned"
        );

        let _display = format!("{}", results);

        for srv_result in &results {
            let _host = srv_result.host();
            let _port = srv_result.port();
            let _priority = srv_result.priority();
            let _weight = srv_result.weight();
            let _display = format!("{}", srv_result);
        }
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

        let _display = format!("{}", results);

        for txt_result in &results {
            let _record_start = txt_result.record_start();
            let _text = txt_result.text();
            let _display = format!("{}", txt_result);
        }
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
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
