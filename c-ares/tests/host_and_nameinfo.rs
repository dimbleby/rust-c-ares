//! Host lookup and name info integration tests.

mod common;

use c_ares::*;
use common::{channel, process_channel};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[test]
#[ignore = "requires network"]
fn get_host_by_address_ipv4() {
    use std::net::IpAddr;

    let mut channel = channel();

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

    let mut channel = channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let addr: IpAddr = "2001:4860:4860::8888".parse().unwrap();
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
fn get_host_by_name_ipv4() {
    let mut channel = channel();

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
        assert!(!format!("{host_results}").is_empty());
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_host_by_name_ipv6() {
    let mut channel = channel();

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

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_name_info_ipv4() {
    use std::net::SocketAddr;

    let mut channel = channel();

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
            assert!(!format!("{name_info}").is_empty());
        },
    );

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_name_info_ipv6() {
    use std::net::SocketAddr;

    let mut channel = channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let addr: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
    channel.get_name_info(&addr, NIFlags::LOOKUPHOST, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let name_info = result.expect("Query failed");
        assert!(name_info.node().is_some(), "No name info node returned");
        assert!(name_info.service().is_none(), "Name info service returned");
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_addrinfo_ipv4() {
    let mut channel = channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let hints = AddrInfoHints {
        family: Some(AddressFamily::INET),
        ..AddrInfoHints::default()
    };
    channel.get_addrinfo("google.com", None, &hints, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let addrinfo = result.expect("Query failed");
        assert!(addrinfo.nodes().count() > 0, "No address nodes returned");
        for node in addrinfo.nodes() {
            assert_eq!(node.family(), AddressFamily::INET);
            assert!(node.ip_addr().is_some());
        }
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_addrinfo_ipv6() {
    let mut channel = channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let hints = AddrInfoHints {
        family: Some(AddressFamily::INET6),
        ..AddrInfoHints::default()
    };
    channel.get_addrinfo("google.com", None, &hints, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let addrinfo = result.expect("Query failed");
        assert!(addrinfo.nodes().count() > 0, "No address nodes returned");
        for node in addrinfo.nodes() {
            assert_eq!(node.family(), AddressFamily::INET6);
            assert!(node.ip_addr().is_some());
        }
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_addrinfo_unspec() {
    let mut channel = channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let hints = AddrInfoHints::default();
    channel.get_addrinfo("google.com", None, &hints, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let addrinfo = result.expect("Query failed");
        assert!(addrinfo.nodes().count() > 0, "No address nodes returned");
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_addrinfo_with_service() {
    let mut channel = channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let hints = AddrInfoHints {
        family: Some(AddressFamily::INET),
        ..AddrInfoHints::default()
    };
    channel.get_addrinfo("google.com", Some("http"), &hints, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let addrinfo = result.expect("Query failed");
        assert!(addrinfo.nodes().count() > 0, "No address nodes returned");
        // When a service is given, the port should be set (80 for http)
        for node in addrinfo.nodes() {
            if let Some(sa) = node.socket_addr() {
                assert_eq!(sa.port(), 80);
            }
        }
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(
        completed.load(Ordering::SeqCst),
        "Query did not complete (get_addrinfo_with_service)"
    );
}

#[test]
#[ignore = "requires network"]
fn get_addrinfo_cnames() {
    let mut channel = channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let hints = AddrInfoHints {
        flags: AddrInfoFlags::CANONNAME,
        family: Some(AddressFamily::INET),
        ..AddrInfoHints::default()
    };
    // www.github.com has a well-known CNAME chain.
    channel.get_addrinfo("www.github.com", None, &hints, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let addrinfo = result.expect("Query failed");
        assert!(addrinfo.nodes().count() > 0, "No address nodes returned");

        let cnames: Vec<_> = addrinfo.cnames().collect();
        assert!(!cnames.is_empty(), "Expected at least one CNAME record");
        for cname in &cnames {
            assert!(!cname.name().is_empty());
            assert!(!cname.alias().is_empty());
            assert!(!format!("{cname}").is_empty());
            assert!(!format!("{cname:?}").is_empty());
        }
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_addrinfo_debug_display() {
    let mut channel = channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let hints = AddrInfoHints {
        family: Some(AddressFamily::INET),
        ..AddrInfoHints::default()
    };
    channel.get_addrinfo("google.com", None, &hints, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let addrinfo = result.expect("Query failed");

        // Exercise Display and Debug on all types.
        let display = format!("{addrinfo}");
        let debug = format!("{addrinfo:?}");
        assert!(display.contains("Nodes:"));
        assert!(debug.contains("AddrInfoResults"));

        for node in addrinfo.nodes() {
            let node_display = format!("{node}");
            let node_debug = format!("{node:?}");
            assert!(!node_display.is_empty());
            assert!(node_debug.contains("AddrInfoNode"));
            assert!(node.ttl() >= 0);
            assert!(node.socktype() >= 0);
            assert!(node.protocol() >= 0);
        }

        // Exercise iterator Debug.
        let iter_debug = format!("{:?}", addrinfo.nodes());
        assert!(iter_debug.contains("AddrInfoNodeIter"));
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_addrinfo_display_with_cnames() {
    let mut channel = channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let hints = AddrInfoHints {
        flags: AddrInfoFlags::CANONNAME,
        family: Some(AddressFamily::INET),
        ..AddrInfoHints::default()
    };
    // www.github.com has a well-known CNAME chain, and CANONNAME gives us a name.
    channel.get_addrinfo("www.github.com", None, &hints, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let addrinfo = result.expect("Query failed");

        // Exercise Display — this hits the name and CNames branches.
        let display = format!("{addrinfo}");
        assert!(
            display.contains("Name:"),
            "expected Name in display: {display}"
        );
        assert!(
            display.contains("CNames:"),
            "expected CNames in display: {display}"
        );
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
#[ignore = "requires network"]
fn get_addrinfo_nonexistent() {
    let mut channel = channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let hints = AddrInfoHints::default();
    // Query a name that will fail at the DNS level, exercising the error path
    // in `get_addrinfo_callback`.
    channel.get_addrinfo("nonexistent.example.invalid", None, &hints, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        assert!(result.is_err(), "Expected an error for nonexistent domain");
    });

    process_channel(&mut channel, Duration::from_secs(5));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
}

#[test]
fn get_addrinfo_null_name() {
    let mut channel = channel();

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    let hints = AddrInfoHints::default();
    channel.get_addrinfo("invalid\0name", None, &hints, move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), Error::EBADNAME);
    });

    // The callback is invoked synchronously for bad names, but wait just in case.
    process_channel(&mut channel, Duration::from_secs(1));

    assert!(completed.load(Ordering::SeqCst), "Callback was not called");
}
