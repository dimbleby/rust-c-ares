use std::collections::HashMap;
use std::io::ErrorKind;
#[cfg(unix)]
use std::os::fd::BorrowedFd;
#[cfg(windows)]
use std::os::windows::io::BorrowedSocket;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

#[cfg(cares1_34)]
use c_ares::{FdEventFlags, FdEvents, ProcessFlags};

use crate::error::Error;
use polling::Event;

// Indicate an interest in read and/or write events.
struct Interest(bool, bool);

// Object returned when the EventLoop is run.  When this is dropped, the EventLoop is stopped.
pub struct EventLoopStopper {
    poller: Arc<polling::Poller>,
    quit: Arc<AtomicBool>,
}

impl EventLoopStopper {
    fn new(poller: Arc<polling::Poller>, quit: Arc<AtomicBool>) -> Self {
        Self { poller, quit }
    }
}

impl Drop for EventLoopStopper {
    fn drop(&mut self) {
        self.quit.store(true, Ordering::Release);
        let _ = self.poller.notify();
    }
}

// The EventLoop sets up a polling::Poller and uses it to wait for events on sockets as directed by
// the c-ares library.
//
// Construction is two-phase: `new()` prepares options (sets the socket state callback), then
// `run()` accepts the already-created channel and starts the background thread.
pub struct EventLoop {
    poller: Arc<polling::Poller>,
    interests: Arc<Mutex<HashMap<c_ares::Socket, Interest>>>,
    quit: Arc<AtomicBool>,

    #[cfg(cares1_34)]
    pending_write: Arc<AtomicBool>,
}

impl EventLoop {
    // Create a new event loop, setting up the socket state callback on `options`.
    //
    // The caller should create the `c_ares::Channel` with these options, then pass the resulting
    // channel to `run()`.
    pub fn new(options: &mut c_ares::Options) -> Result<Self, Error> {
        // Create a polling::Poller on which to wait for events, and a hashmap to record which
        // sockets we are interested in.
        let poller = Arc::new(polling::Poller::new()?);
        let interests: HashMap<c_ares::Socket, Interest> = HashMap::new();
        let interests = Arc::new(Mutex::new(interests));

        // Whenever c-ares tells us that it cares about a socket, we'll update the poller
        // accordingly.
        //
        // Safety: we are trusting c-ares to give us a socket that is valid and that will remain
        // open until we are asked to drop our interest.
        {
            let poller = Arc::clone(&poller);
            let interests = Arc::clone(&interests);
            let sock_callback = move |socket: c_ares::Socket, readable: bool, writable: bool| {
                let mut interests = interests.lock().unwrap();
                if !readable && !writable {
                    if interests.remove(&socket).is_some() {
                        let source = unsafe { borrow_socket(socket) };
                        poller
                            .delete(source)
                            .expect("Failed to remove socket from poller");
                    }
                } else {
                    let key = usize::try_from(socket).unwrap();
                    let event = Event::new(key, readable, writable);
                    let interest = Interest(readable, writable);
                    if interests.insert(socket, interest).is_none() {
                        unsafe {
                            poller
                                .add(socket, event)
                                .expect("failed to add socket to poller");
                        }
                    } else {
                        let source = unsafe { borrow_socket(socket) };
                        poller
                            .modify(source, event)
                            .expect("failed to update interest");
                    }
                }
            };
            options.set_socket_state_callback(sock_callback);
        }

        let event_loop = Self {
            poller,
            interests,
            quit: Arc::new(AtomicBool::new(false)),
            #[cfg(cares1_34)]
            pending_write: Arc::new(AtomicBool::new(false)),
        };
        Ok(event_loop)
    }

    // Run the event loop with the given channel.
    pub fn run(self, ares_channel: Arc<Mutex<c_ares::Channel>>) -> EventLoopStopper {
        // Set up the pending-write optimization.
        #[cfg(cares1_34)]
        {
            let pending_write = Arc::clone(&self.pending_write);
            let poller = Arc::clone(&self.poller);
            let pending_write_callback = move || {
                pending_write.store(true, Ordering::Release);
                poller
                    .notify()
                    .expect("Failed to notify poller of pending write");
            };
            ares_channel
                .lock()
                .unwrap()
                .set_pending_write_callback(pending_write_callback);
        }

        // When a new query is enqueued, wake the event loop so it can
        // recompute the timeout.
        #[cfg(cares1_35)]
        {
            let poller = Arc::clone(&poller);
            let query_enqueue_callback = move || {
                poller
                    .notify()
                    .expect("Failed to notify poller of query enqueue");
            };
            ares_channel.set_query_enqueue_callback(query_enqueue_callback);
        }

        // Create a stopper.
        let stopper = EventLoopStopper::new(Arc::clone(&self.poller), Arc::clone(&self.quit));

        thread::spawn(|| self.event_loop_thread(ares_channel));
        stopper
    }

    // Event loop thread - waits for events, and handles them.
    //
    // Takes `ares_channel` by value because this method is the body of a
    // dedicated `thread::spawn` closure and runs for the thread's full
    // lifetime.
    #[allow(clippy::needless_pass_by_value)]
    fn event_loop_thread(self, ares_channel: Arc<Mutex<c_ares::Channel>>) {
        let mut events = polling::Events::new();

        // Without the query enqueue callback we have no way to be woken when
        // a new query arrives on an existing connection, so we cap the poll
        // interval.  With the callback we can block until needed.
        #[cfg(not(cares1_35))]
        const MAX_POLL: Option<Duration> = Some(Duration::from_millis(500));
        #[cfg(cares1_35)]
        const MAX_POLL: Option<Duration> = None;

        loop {
            // Ask c-ares how long until the next timeout fires.
            let timeout = ares_channel.lock().unwrap().timeout(MAX_POLL);

            // Wait for something to happen.
            events.clear();
            let results = self.poller.wait(&mut events, timeout);

            // If we're asked to quit, then quit.
            if self.quit.load(Ordering::Acquire) {
                break;
            }

            // Interrupted is OK, we just retry.  Other errors are unexpected.
            if let Err(ref err) = results
                && err.kind() == ErrorKind::Interrupted
            {
                continue;
            }
            results.expect("Poll failed");

            // Process any pending write.
            #[cfg(cares1_34)]
            if self.pending_write.swap(false, Ordering::AcqRel) {
                ares_channel.lock().unwrap().process_pending_write();
            }

            // Process any events.
            handle_events(&ares_channel, &events);

            // `polling` always operates in oneshot mode, but c-ares expects us to maintain an
            // interest in sockets until told otherwise.
            //
            // So re-assert our interest in all reported sockets.
            for event in events.iter() {
                let socket = c_ares::Socket::try_from(event.key).unwrap();
                let interests = self.interests.lock().unwrap();
                if let Some(Interest(readable, writable)) = interests.get(&socket) {
                    // Safety: we trust that since c-ares hasn't yet told us that it is done
                    // with this socket, it's still open.
                    let source = unsafe { borrow_socket(socket) };
                    let new_event = Event::new(event.key, *readable, *writable);
                    self.poller
                        .modify(source, new_event)
                        .expect("failed to renew interest");
                }
            }
        }
    }
}

#[cfg(cares1_34)]
fn handle_events(ares_channel: &Mutex<c_ares::Channel>, events: &polling::Events) {
    let mut fd_events: Vec<FdEvents> = Vec::with_capacity(events.capacity().into());
    let fd_events_iter = events.iter().map(|event| {
        let socket = c_ares::Socket::try_from(event.key).unwrap();
        let mut event_flags = FdEventFlags::empty();
        if event.readable {
            event_flags.insert(FdEventFlags::READ);
        }
        if event.writable {
            event_flags.insert(FdEventFlags::WRITE);
        }
        FdEvents::new(socket, event_flags)
    });
    fd_events.extend(fd_events_iter);

    let _ = ares_channel
        .lock()
        .unwrap()
        .process_fds(&fd_events, ProcessFlags::empty());
}

#[cfg(not(cares1_34))]
fn handle_events(ares_channel: &Mutex<c_ares::Channel>, events: &polling::Events) {
    let mut acted = false;
    for event in events.iter() {
        let socket = c_ares::Socket::try_from(event.key).unwrap();

        let rfd = event.readable.then_some(socket);
        let wfd = event.writable.then_some(socket);

        ares_channel.lock().unwrap().process_fd(rfd, wfd);
        acted = true;
    }

    if !acted {
        // No events.  Have c-ares process any timeouts.
        ares_channel.lock().unwrap().process_fd(None, None);
    }
}

#[cfg(unix)]
unsafe fn borrow_socket(socket: c_ares::Socket) -> impl polling::AsSource {
    unsafe { BorrowedFd::borrow_raw(socket) }
}

#[cfg(windows)]
unsafe fn borrow_socket(socket: c_ares::Socket) -> impl polling::AsSource {
    unsafe { BorrowedSocket::borrow_raw(socket) }
}
