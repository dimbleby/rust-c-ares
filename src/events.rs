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
