use crate::types::Socket;
use bitflags::bitflags;

bitflags!(
    /// Events used by FdEvents.
    #[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
    pub struct FdEventFlags: u32 {
        /// Read event (including disconnect/error).
        const Read = c_ares_sys::ares_fd_eventflag_t::ARES_FD_EVENT_READ as u32;
        /// Write event.
        const Write = c_ares_sys::ares_fd_eventflag_t::ARES_FD_EVENT_WRITE as u32;
    }
);

bitflags!(
    /// Flags used by [`crate::Channel::process_fds()`].
    #[derive(Copy, Clone, Eq, PartialEq, Debug, Hash, PartialOrd, Ord)]
    pub struct ProcessFlags: u32 {
        /// Skip any processing unrelated to the file descriptor events passed in.
        const SkipNonFd = c_ares_sys::ares_process_flag_t::ARES_PROCESS_FLAG_SKIP_NON_FD as u32;
    }
);

/// Type holding a file descriptor and mask of events, used by [`crate::Channel::process_fds()`].
#[repr(transparent)]
pub struct FdEvents(c_ares_sys::ares_fd_events_t);

impl FdEvents {
    /// Returns a new `FdEvents`.
    pub fn new(socket: Socket, events: FdEventFlags) -> Self {
        let events = c_ares_sys::ares_fd_events_t {
            fd: socket,
            events: events.bits(),
        };
        FdEvents(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fd_event_flags_empty() {
        let flags = FdEventFlags::empty();
        assert!(flags.is_empty());
    }

    #[test]
    fn fd_event_flags_read() {
        let flags = FdEventFlags::Read;
        assert!(flags.contains(FdEventFlags::Read));
        assert!(!flags.contains(FdEventFlags::Write));
    }

    #[test]
    fn fd_event_flags_write() {
        let flags = FdEventFlags::Write;
        assert!(flags.contains(FdEventFlags::Write));
        assert!(!flags.contains(FdEventFlags::Read));
    }

    #[test]
    fn fd_event_flags_combined() {
        let flags = FdEventFlags::Read | FdEventFlags::Write;
        assert!(flags.contains(FdEventFlags::Read));
        assert!(flags.contains(FdEventFlags::Write));
    }

    #[test]
    fn process_flags_empty() {
        let flags = ProcessFlags::empty();
        assert!(flags.is_empty());
    }

    #[test]
    fn process_flags_skip_non_fd() {
        let flags = ProcessFlags::SkipNonFd;
        assert!(flags.contains(ProcessFlags::SkipNonFd));
    }

    #[test]
    fn fd_events_new() {
        let events = FdEvents::new(42, FdEventFlags::Read);
        assert_eq!(events.0.fd, 42);
        assert_eq!(events.0.events, FdEventFlags::Read.bits());
    }
}
