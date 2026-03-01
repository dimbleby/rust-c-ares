//! Channel feature integration tests (concurrent queries, callbacks).

#![cfg(all(unix, any(target_os = "linux", target_os = "android")))]

mod common;

use c_ares::*;
use common::process_channel;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

#[test]
#[ignore = "requires network"]
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

    assert!(
        a_completed.load(Ordering::SeqCst),
        "A query did not complete"
    );
    assert!(
        aaaa_completed.load(Ordering::SeqCst),
        "AAAA query did not complete"
    );
    assert!(
        mx_completed.load(Ordering::SeqCst),
        "MX query did not complete"
    );
}

#[cfg(cares1_34)]
#[test]
#[ignore = "requires network"]
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

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    // Note: The callback may or may not be invoked - we just test that setting it works
}

#[cfg(cares1_29)]
#[test]
#[ignore = "requires network"]
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

    channel.set_server_state_callback(
        move |server: &str, success: bool, flags: ServerStateFlags| {
            callback_count_clone.fetch_add(1, Ordering::SeqCst);
            // Verify callback receives valid data
            assert!(!server.is_empty(), "Server should not be empty");
            // flags should contain UDP or TCP
            let has_transport =
                flags.contains(ServerStateFlags::UDP) || flags.contains(ServerStateFlags::TCP);
            assert!(
                has_transport || flags.is_empty(),
                "Flags should indicate transport"
            );
            let _ = success; // success can be true or false
        },
    );

    let completed = Arc::new(AtomicBool::new(false));
    let completed_clone = completed.clone();

    channel.query_a("google.com", move |result| {
        completed_clone.store(true, Ordering::SeqCst);
        let _ = result;
    });

    process_channel(&mut channel, Duration::from_secs(3));

    assert!(completed.load(Ordering::SeqCst), "Query did not complete");
    assert!(
        callback_count.load(Ordering::SeqCst) > 0,
        "Server state callback should be invoked"
    );
}
