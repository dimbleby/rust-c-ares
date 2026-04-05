use std::any::Any;
use std::cell::RefCell;
use std::panic::{self, AssertUnwindSafe};

thread_local! {
    static LAST_ERROR: RefCell<Option<Box<dyn Any + Send>>> = RefCell::new(None);
}

pub fn catch<T, F: FnOnce() -> T>(f: F) -> Option<T> {
    if LAST_ERROR
        .try_with(|slot| slot.borrow().is_some())
        .unwrap_or(false)
    {
        return None;
    }

    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(ret) => Some(ret),
        Err(e) => {
            LAST_ERROR.with(|slot| *slot.borrow_mut() = Some(e));
            None
        }
    }
}

pub fn propagate() {
    if let Ok(Some(t)) = LAST_ERROR.try_with(|slot| slot.borrow_mut().take()) {
        panic::resume_unwind(t)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catch_returns_value_on_success() {
        let result = catch(|| 42);
        assert_eq!(result, Some(42));
    }

    #[test]
    fn catch_captures_panic() {
        let result = catch(|| -> i32 { panic!("test panic") });
        assert_eq!(result, None);

        // Clean up the stored panic so it doesn't affect other tests.
        propagate_if_stored();
    }

    #[test]
    fn propagate_resumes_stored_panic() {
        let result = catch(|| -> i32 { panic!("stored panic") });
        assert_eq!(result, None);

        let caught = panic::catch_unwind(AssertUnwindSafe(propagate));
        assert!(caught.is_err(), "propagate should have resumed the panic");
    }

    #[test]
    fn catch_skips_when_prior_panic_stored() {
        // Store a panic.
        let _ = catch(|| -> i32 { panic!("first panic") });

        // A second catch should return None without running the closure.
        let mut ran = false;
        let result = catch(|| {
            ran = true;
            99
        });
        assert_eq!(result, None);
        assert!(!ran, "closure should not have been invoked");

        // Clean up.
        propagate_if_stored();
    }

    #[test]
    fn propagate_is_noop_when_no_panic() {
        // Should not panic.
        propagate();
    }

    /// Helper: drain any stored panic without actually unwinding.
    fn propagate_if_stored() {
        let _ = panic::catch_unwind(AssertUnwindSafe(propagate));
    }
}
