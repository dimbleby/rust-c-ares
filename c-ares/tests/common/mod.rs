#[cfg(cares1_28)]
use c_ares::*;
#[cfg(cares1_28)]
use std::time::Duration;

/// Create a `Channel` with the c-ares built-in event thread enabled.
///
/// Panics if c-ares was not built with thread safety support.
#[cfg(cares1_28)]
pub fn event_thread_channel() -> Channel {
    assert!(
        c_ares::thread_safety(),
        "c-ares was not built with thread safety; cannot use event thread"
    );

    let mut options = Options::new();
    options
        .set_flags(Flags::STAYOPEN)
        .set_timeout(Duration::from_millis(2000))
        .set_tries(2)
        .set_event_thread(EventSys::Default);

    let mut channel = Channel::with_options(options).expect("Failed to create channel");
    channel
        .set_servers(["8.8.8.8"])
        .expect("Failed to set servers");
    channel
}
