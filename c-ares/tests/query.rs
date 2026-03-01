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
        assert!(!format!("{}", results).is_empty());

        let mut ipv4_valid = false;
        let mut ttl_valid = false;
        for a_result in &results {
            if !a_result.ipv4().is_unspecified() {
                ipv4_valid = true;
            }
            if a_result.ttl() >= 0 {
                ttl_valid = true;
            }
            assert!(!format!("{}", a_result).is_empty());
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
        assert!(!format!("{}", results).is_empty());

        let mut ipv6_valid = false;
        for aaaa_result in &results {
            if !aaaa_result.ipv6().is_unspecified() {
                ipv6_valid = true;
            }
            assert!(aaaa_result.ttl() >= 0);
            assert!(!format!("{}", aaaa_result).is_empty());
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

        assert!(!format!("{}", results).is_empty());

        for caa_result in &results {
            assert!(!caa_result.critical());
            assert!(!caa_result.property().is_empty());
            assert!(!caa_result.value().is_empty());
            assert!(!format!("{}", caa_result).is_empty());
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
        assert!(results.aliases().count() > 0, "No aliases returned");
        assert!(!format!("{}", results).is_empty());
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

        assert!(!format!("{}", results).is_empty());

        for mx_result in &results {
            assert!(!mx_result.host().is_empty());
            assert!(mx_result.priority() > 0);
            assert!(!format!("{}", mx_result).is_empty());
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

        assert!(!format!("{}", results).is_empty());

        for naptr_result in &results {
            assert!(!naptr_result.flags().is_empty());
            assert!(!naptr_result.service_name().is_empty());
            assert!(naptr_result.reg_exp().is_empty());
            assert!(!naptr_result.replacement_pattern().is_empty());
            let _order = naptr_result.order();
            let _preference = naptr_result.preference();
            assert!(!format!("{}", naptr_result).is_empty());
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
        assert!(results.aliases().count() > 0, "No NS aliases returned");
        assert!(!format!("{}", results).is_empty());
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
        assert!(results.aliases().count() > 0, "No PTR aliases returned");
        assert!(!format!("{}", results).is_empty());
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
        assert!(!soa.hostmaster().is_empty());
        assert!(soa.serial() > 0);
        assert!(soa.refresh() > 0);
        assert!(soa.retry() > 0);
        assert!(soa.expire() > 0);
        assert!(soa.min_ttl() > 0);
        assert!(!format!("{}", soa).is_empty());
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

        assert!(!format!("{}", results).is_empty());

        for srv_result in &results {
            assert!(!srv_result.host().is_empty());
            assert!(srv_result.port() > 0);
            let _priority = srv_result.priority();
            let _weight = srv_result.weight();
            assert!(!format!("{}", srv_result).is_empty());
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

        assert!(!format!("{}", results).is_empty());

        for txt_result in &results {
            assert!(!txt_result.text().is_empty());
            let _record_start = txt_result.record_start();
            assert!(!format!("{}", txt_result).is_empty());
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
        assert!(results.iter().count() > 0, "No URI records returned");
        assert!(!format!("{}", results).is_empty());

        for uri_result in &results {
            assert!(!uri_result.uri().is_empty());
            let _priority = uri_result.priority();
            let _weight = uri_result.weight();
            assert!(uri_result.ttl() >= 0);
            assert!(!format!("{}", uri_result).is_empty());
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
