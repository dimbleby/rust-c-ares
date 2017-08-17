use std::any::Any;
use std::cell::RefCell;
use std::panic::{self, AssertUnwindSafe};

thread_local! {
    static LAST_ERROR: RefCell<Option<Box<Any + Send>>> = RefCell::new(None);
    static UNWINDING: RefCell<bool> = RefCell::new(false);
}

pub fn catch<T, F: FnOnce() -> T>(f: F) -> Option<T> {
    if LAST_ERROR.with(|slot| slot.borrow().is_some()) {
        return None
    }

    if UNWINDING.with(|slot| *slot.borrow()) {
        return None
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
    if let Some(t) = LAST_ERROR.with(|slot| slot.borrow_mut().take()) {
        UNWINDING.with(|slot| *slot.borrow_mut() = true);
        panic::resume_unwind(t);
    }
}
