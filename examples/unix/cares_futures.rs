// A variation on cares-event-loop.rs.
//
// Here we:
//
// - Have the event loop be run by a `Resolver`, hiding away the event loop
// details from the writer of `main()`.
//
// - Transform the callback-based c-ares interface into a futures-style.
extern crate c_ares;
extern crate futures;
extern crate mio;
extern crate tokio_core;

use std::collections::HashSet;
use std::error::Error;
use std::sync::{
    Arc,
    Mutex,
};
use std::thread;
use std::time::Duration;

use self::futures::Future;

// The EventLoop will set up a mio::Poll and use it to wait for the following:
//
// -  messages telling it which file descriptors it should be interested in.
//    These file descriptors are then registered (or deregistered) with the
//    mio::Poll as required.
//
// -  events telling it that something has happened on one of these file
//    descriptors.  When this happens, it tells the c_ares::Channel about it.
//
// -  a message telling it to shut down.
struct EventLoop {
    poll: mio::Poll,
    msg_channel: mio::channel::Receiver<Message>,
    tracked_fds: HashSet<c_ares::Socket>,
    ares_channel: Arc<Mutex<c_ares::Channel>>,
    quit: bool,
}

// Messages for the event loop.
#[derive(Debug)]
enum Message {
    // 'Notify me when this file descriptor becomes readable, or writable'.
    // The first bool is for 'readable' and the second is for 'writable'.  It's
    // allowed to set both of these - or neither, meaning 'I am no longer
    // interested in this file descriptor'.
    RegisterInterest(c_ares::Socket, bool, bool),

    // 'Shut down'.
    ShutDown,
}

// We also use Token(fd) for file descriptors, so this relies on zero not
// being a valid file descriptor for c-ares to use.  Zero is stdin, so that's
// true.
const CHANNEL: mio::Token = mio::Token(0);

impl EventLoop {
    // Create a new event loop.
    pub fn new(
        ares_channel: Arc<Mutex<c_ares::Channel>>,
        rx: mio::channel::Receiver<Message>) -> EventLoop {
        let poll = mio::Poll::new().expect("Failed to create poll");
        poll.register(&rx, CHANNEL, mio::Ready::readable(), mio::PollOpt::edge())
            .expect("failed to register channel with poll");

        EventLoop {
            poll: poll,
            msg_channel: rx,
            tracked_fds: HashSet::<c_ares::Socket>::new(),
            ares_channel: ares_channel,
            quit: false,
        }
    }

    // Run the event loop.
    pub fn run(self) -> thread::JoinHandle<()> {
        thread::spawn(|| self.event_loop_thread())
    }

    // Event loop thread - waits for events, and handles them.
    fn event_loop_thread(mut self) {
        let mut events = mio::Events::with_capacity(16);
        loop {
            // Wait for something to happen.
            let timeout = Duration::from_millis(500);
            let results = self.poll
                .poll(&mut events, Some(timeout))
                .expect("poll failed");

            // Process whatever happened.
            match results {
                0 => {
                    // No events - must be a timeout.  Tell c-ares about it.
                    self.ares_channel.lock().unwrap().process_fd(
                        c_ares::SOCKET_BAD,
                        c_ares::SOCKET_BAD);
                },
                _ => {
                    // Process events.  One of them might have asked us to quit.
                    for event in &events {
                        self.handle_event(&event);
                        if self.quit { return }
                    }
                }
            }
        }
    }

    // Handle a single event.
    fn handle_event(&mut self, event: &mio::Event) {
        match event.token() {
            CHANNEL => {
                // The channel is readable.
                self.handle_messages()
            },

            mio::Token(fd) => {
                // Sockets became readable or writable - tell c-ares.
                let rfd = if event.kind().is_readable() {
                    fd as c_ares::Socket
                } else {
                    c_ares::SOCKET_BAD
                };
                let wfd = if event.kind().is_writable() {
                    fd as c_ares::Socket
                } else {
                    c_ares::SOCKET_BAD
                };
                self.ares_channel.lock().unwrap().process_fd(rfd, wfd);
            }
        }
    }

    // Process messages incoming on the channel.
    fn handle_messages(&mut self) {
        loop {
            match self.msg_channel.try_recv() {
                Ok(Message::RegisterInterest(fd, readable, writable)) => {
                    // Instruction to do something with a file descriptor.
                    let efd = mio::unix::EventedFd(&fd);
                    if !readable && !writable {
                        self.tracked_fds.remove(&fd);
                        self.poll
                            .deregister(&efd)
                            .expect("failed to deregister interest");
                    } else {
                        let token = mio::Token(fd as usize);
                        let mut interest = mio::Ready::none();
                        if readable { interest.insert(mio::Ready::readable()) }
                        if writable { interest.insert(mio::Ready::writable()) }
                        let register_result = if !self.tracked_fds.insert(fd) {
                            self.poll
                                .reregister(&efd, token, interest, mio::PollOpt::edge())
                        } else {
                            self.poll
                                .register(&efd, token, interest, mio::PollOpt::edge())
                        };
                        register_result.expect("failed to register interest");
                    }
                },

                Ok(Message::ShutDown) => {
                    // Instruction to shut down.
                    self.quit = true;
                    break
                },

                // No more instructions.
                Err(_) => break,
            }
        }
    }
}

// The Resolver is the interface by which users make DNS queries.
struct Resolver {
    ares_channel: Arc<Mutex<c_ares::Channel>>,
    event_loop_channel: mio::channel::Sender<Message>,
    event_loop_handle: Option<thread::JoinHandle<()>>,
}

impl Resolver {
    // Create a new Resolver.
    pub fn new() -> Resolver {
        // Whenever c-ares tells us what to do with a file descriptor, we'll
        // send that request along, in a message to the event loop thread.
        let (tx, rx) = mio::channel::channel();
        let tx_clone = tx.clone();
        let sock_callback =
            move |fd: c_ares::Socket, readable: bool, writable: bool| {
                let _ = tx_clone.send(
                    Message::RegisterInterest(fd, readable, writable));
            };

        // Create a c_ares::Channel.
        let mut options = c_ares::Options::new();
        options
            .set_socket_state_callback(sock_callback)
            .set_flags(c_ares::flags::STAYOPEN | c_ares::flags::EDNS)
            .set_timeout(500)
            .set_tries(3);
        let mut ares_channel = c_ares::Channel::new(options)
            .expect("Failed to create channel");
        ares_channel.set_servers(&["8.8.8.8"]).expect("Failed to set servers");
        let locked_channel = Arc::new(Mutex::new(ares_channel));

        // Create and run the event loop.
        let channel_clone = locked_channel.clone();
        let event_loop = EventLoop::new(channel_clone, rx);
        let handle = event_loop.run();

        // Return the Resolver.
        Resolver {
            ares_channel: locked_channel,
            event_loop_channel: tx,
            event_loop_handle: Some(handle),
        }
    }

    // A CNAME query.  Returns a future that will resolve to hold the result.
    pub fn query_cname(&self, name: &str)
        -> futures::BoxFuture<c_ares::CNameResults, c_ares::AresError> {
        let (c, p) = futures::oneshot();
        self.ares_channel.lock().unwrap().query_cname(name, move |result| {
            c.complete(result);
        });
        p.map_err(|_| c_ares::AresError::ECANCELLED)
            .and_then(futures::done)
            .boxed()
    }

    // An MX query.  Returns a future that will resolve to hold the result.
    pub fn query_mx(&self, name: &str)
        -> futures::BoxFuture<c_ares::MXResults, c_ares::AresError> {
        let (c, p) = futures::oneshot();
        self.ares_channel.lock().unwrap().query_mx(name, move |result| {
            c.complete(result);
        });
        p.map_err(|_| c_ares::AresError::ECANCELLED)
            .and_then(futures::done)
            .boxed()
    }

    // A NAPTR query.  Returns a future that will resolve to hold the result.
    pub fn query_naptr(&self, name: &str)
        -> futures::BoxFuture<c_ares::NAPTRResults, c_ares::AresError> {
        let (c, p) = futures::oneshot();
        self.ares_channel.lock().unwrap().query_naptr(name, move |result| {
            c.complete(result);
        });
        p.map_err(|_| c_ares::AresError::ECANCELLED)
            .and_then(futures::done)
            .boxed()
    }
}

impl Drop for Resolver {
    fn drop(&mut self) {
        // Shut down the event loop and wait for it to finish.
        self.event_loop_channel
            .send(Message::ShutDown)
            .expect("failed to request event loop to shut down");
        if let Some(handle) = self.event_loop_handle.take() {
           handle.join().expect("failed to shut down event loop");
        }
    }
}

fn print_cname_result(
    result: &Result<c_ares::CNameResults, c_ares::AresError>) {
    match *result {
        Err(ref e) => {
            println!("CNAME lookup failed with error '{}'", e.description());
        }
        Ok(ref cname_results) => {
            println!("Successful CNAME lookup...");
            println!("Hostname: {}", cname_results.hostname());
            for alias in cname_results.aliases() {
                println!("Alias: {}", alias);
            }
        }
    }
}

fn print_mx_results(result: &Result<c_ares::MXResults, c_ares::AresError>) {
    match *result {
        Err(ref e) => {
            println!("MX lookup failed with error '{}'", e.description());
        }
        Ok(ref mx_results) => {
            println!("Successful MX lookup...");
            for mx_result in mx_results {
                println!(
                    "host {}, priority {}",
                    mx_result.host(),
                    mx_result.priority());
            }
        }
    }
}

fn print_naptr_results(
    result: &Result<c_ares::NAPTRResults, c_ares::AresError>) {
    match *result {
        Err(ref e) => {
            println!("NAPTR lookup failed with error '{}'", e.description());
        }
        Ok(ref naptr_results) => {
            println!("Successful NAPTR lookup...");
            for naptr_result in naptr_results {
                println!("flags: {}", naptr_result.flags());
                println!("service name: {}", naptr_result.service_name());
                println!("regular expression: {}", naptr_result.reg_exp());
                println!(
                    "replacement pattern: {}",
                    naptr_result.replacement_pattern());
                println!("order: {}", naptr_result.order());
                println!("preference: {}", naptr_result.preference());
            }
        }
    }
}

pub fn main() {
    // Create a tokio event loop, and a Resolver.  Then make some requests.
    let mut l = tokio_core::reactor::Core::new().unwrap();
    let resolver = Resolver::new();
    let query = resolver.query_cname("dimbleby.github.io");
    let result = l.run(query);
    println!("");
    print_cname_result(&result);

    let query = resolver.query_mx("gmail.com");
    let result = l.run(query);
    println!("");
    print_mx_results(&result);

    let query = resolver.query_naptr("apple.com");
    let result = l.run(query);
    println!("");
    print_naptr_results(&result);
}
