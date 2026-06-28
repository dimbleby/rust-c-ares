use std::panic::{self, AssertUnwindSafe};

/// Run `f`, aborting the process if it panics.
///
/// `f` is a user callback that c-ares invokes across an `extern "C"` boundary,
/// where unwinding is not permitted.  Rather than try to smuggle a panic back
/// to a Rust caller - which is impossible when c-ares runs callbacks on its own
/// event thread - we treat a panicking callback as fatal and abort.
///
/// The panic payload is dropped without inspection because the default panic
/// hook has already reported the panic (thread, location, message) to stderr
/// by the time `catch_unwind` returns it, so there is nothing left to surface.
pub fn abort_on_panic<T>(f: impl FnOnce() -> T) -> T {
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(value) => value,
        Err(_already_reported_by_panic_hook) => std::process::abort(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn returns_value_on_success() {
        assert_eq!(abort_on_panic(|| 42), 42);
    }
}
