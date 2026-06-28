//! A panic in a user callback must abort the process, not be smuggled back
//! across the c-ares FFI boundary or silently swallowed.

use std::process::{Command, Stdio};

const CHILD_ENV: &str = "C_ARES_RESOLVER_PANIC_ABORT_CHILD";

#[test]
fn panicking_callback_aborts_the_process() {
    if std::env::var_os(CHILD_ENV).is_some() {
        // Child: configure no servers so the query completes synchronously with
        // ENOSERVER, invoking our callback on this thread - where it panics.
        let resolver = c_ares_resolver::Resolver::new().unwrap();
        let _ = resolver.set_servers(std::iter::empty::<&str>());
        resolver.query_a("example.com", |_result| panic!("callback panic"));

        // We should already have aborted; if not, exit cleanly so the parent's
        // assertion fails loudly.
        std::thread::sleep(std::time::Duration::from_secs(2));
        return;
    }

    let status = Command::new(std::env::current_exe().expect("current test exe"))
        .args([
            "--exact",
            "panicking_callback_aborts_the_process",
            "--quiet",
        ])
        .env(CHILD_ENV, "1")
        .stderr(Stdio::null())
        .status()
        .expect("failed to run child");

    assert!(
        !status.success(),
        "a panicking callback did not abort the child process"
    );

    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(status.signal(), Some(6), "expected SIGABRT");
    }
}
