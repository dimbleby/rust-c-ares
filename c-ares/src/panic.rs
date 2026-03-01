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
