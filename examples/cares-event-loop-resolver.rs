// A variation on cares-event-loop.rs.
//
// Here we:
//
// - Have the event loop take an `Arc<Mutex<Channel>>`, so that even after it
// is running we still have the ability to submit new queries
//
// - Have the event loop be run by a `Resolver`, hiding away the event loop
// details from the writer of `main()`.
//
// - Show one way of transforming the asynchronous c-ares interface into
// a synchronous, blocking interface by using a std::sync::mpsc::channel.
extern crate c_ares;
extern crate mio;

use c_ares::HostEntResults;
use std::collections::HashSet;
use std::error::Error;
use std::mem;
use std::os::unix::io;
use std::sync::{
    Arc,
    Mutex,
    mpsc,
};
use std::thread;

// Messages for the event loop.
enum CAresHandlerMessage {
    // 'Notify me when this file descriptor becomes readable, or writable'
    // The first bool is for 'readable' and the second is for 'writable'.  It's
    // allowed to set both of these - or neither, meaning 'I am no longer
    // interested in this file descriptor'.
    RegisterInterest(io::RawFd, bool, bool),

    // 'Shut down'.
    ShutDown,
}

struct CAresEventHandler {
    ares_channel: Arc<Mutex<c_ares::Channel>>,
    tracked_fds: HashSet<io::RawFd>,
}

impl CAresEventHandler {
    fn new(ares_channel: Arc<Mutex<c_ares::Channel>>) -> CAresEventHandler {
        CAresEventHandler {
            ares_channel: ares_channel,
            tracked_fds: HashSet::new(),
        }
    }
}

impl mio::Handler for CAresEventHandler {
    type Timeout = ();
    type Message = CAresHandlerMessage;

    // mio notifies us that a file descriptor is readable or writable, so we
    // tell the Channel the same.
    fn ready(
        &mut self,
        _event_loop: &mut mio::EventLoop<CAresEventHandler>,
        token: mio::Token,
        events: mio::EventSet) {
        let fd = token.as_usize() as io::RawFd;
        let read_fd = if events.is_readable() {
            fd
        } else {
            c_ares::INVALID_FD
        };
        let write_fd = if events.is_writable() {
            fd
        } else {
            c_ares::INVALID_FD
        };
        self.ares_channel.lock().unwrap().process_fd(read_fd, write_fd);
    }

    // Process received messages.  Either:
    // - we're asked to register interest (or non-interest) in a file
    // descriptor
    // - we're asked to shut down the event loop.
    fn notify(
        &mut self,
        event_loop:&mut mio::EventLoop<CAresEventHandler>,
        msg: Self::Message) {
        match msg {
            CAresHandlerMessage::RegisterInterest(fd, readable, writable) => {
                let io = mio::Io::from(fd);
                if !readable && !writable {
                    self.tracked_fds.remove(&fd);
                    event_loop
                        .deregister(&io)
                        .ok()
                        .expect("failed to deregister interest");
                } else {
                    let mut interest = mio::EventSet::none();
                    if readable {
                        interest = interest | mio::EventSet::readable();
                    }
                    if writable {
                        interest = interest | mio::EventSet::writable();
                    }
                    let token = mio::Token(fd as usize);
                    let register_result = if !self.tracked_fds.insert(fd) {
                        event_loop
                            .reregister(
                                &io,
                                token,
                                interest,
                                mio::PollOpt::edge())
                   } else {
                        event_loop
                            .register_opt(
                                &io,
                                token,
                                interest,
                                mio::PollOpt::edge())
                    };
                    register_result.ok().expect("failed to register interest");
                }

                // Don't accidentally close the file descriptor by dropping io!
                mem::forget(io);
            },

            CAresHandlerMessage::ShutDown => event_loop.shutdown(),
        }
    }

    // We run a recurring timer so that we can spot non-responsive servers.
    //
    // In that case we won't get a callback saying that anything is happening
    // on any file descriptor, but nevertheless need to give the Channel an
    // opportunity to notice that it has timed-out requests pending.
    fn timeout(
        &mut self,
        event_loop: &mut mio::EventLoop<CAresEventHandler>,
        _timeout: Self::Timeout) {
        event_loop.timeout_ms((), 500).unwrap();
        self.ares_channel
            .lock()
            .unwrap()
            .process_fd(c_ares::INVALID_FD, c_ares::INVALID_FD);
    }
}

struct Resolver {
    ares_channel: Arc<Mutex<c_ares::Channel>>,
    event_loop_channel: mio::Sender<CAresHandlerMessage>,
    event_loop_handle: Option<thread::JoinHandle<()>>,
}

impl Resolver {
    // Create a new Resolver.
    pub fn new() -> Resolver {
        // Create an event loop.
        let mut event_loop = mio::EventLoop::new()
            .ok()
            .expect("failed to create event loop");
        let event_loop_channel = event_loop.channel();

        // Socket state callback for the c_ares::Channel will be to kick the
        // event loop.
        let event_loop_channel_clone = event_loop_channel.clone();
        let sock_callback =
            move |fd: io::RawFd, readable: bool, writable: bool| {
                let _ = event_loop_channel_clone
                    .send(
                        CAresHandlerMessage::RegisterInterest(
                            fd,
                            readable,
                            writable));
            };

        // Create a c_ares::Channel.
        let mut options = c_ares::Options::new();
        options
            .set_socket_state_callback(sock_callback)
            .set_flags(c_ares::flags::STAYOPEN | c_ares::flags::EDNS)
            .set_timeout(500)
            .set_tries(3);
        let ares_channel = c_ares::Channel::new(options)
            .ok()
            .expect("Failed to create channel");
        let locked_channel = Arc::new(Mutex::new(ares_channel));

        // Set the first instance of the recurring timer on the event loop.
        event_loop.timeout_ms((), 500).unwrap();

        // Kick off the event loop.
        let mut event_handler = CAresEventHandler::new(locked_channel.clone());
        let event_loop_handle = thread::spawn(move || {
            event_loop
                .run(&mut event_handler)
                .ok()
                .expect("failed to run event loop")
        });

        Resolver {
            ares_channel: locked_channel,
            event_loop_channel: event_loop_channel,
            event_loop_handle: Some(event_loop_handle),
        }
    }

    // A blocking CNAME query.  Achieve this by having the callback send the
    // result to a std::sync::mpsc::channel, and waiting on that channel.
    pub fn query_cname(&self, name: &str)
        -> Result<c_ares::CNameResults, c_ares::AresError> {
        let (tx, rx) = mpsc::channel();
        self.ares_channel.lock().unwrap().query_cname(name, move |result| {
            tx.send(result).unwrap();
        });
        rx.recv().unwrap()
    }

    // A blocking MX query.
    pub fn query_mx(&self, name: &str)
        -> Result<c_ares::MXResults, c_ares::AresError> {
        let (tx, rx) = mpsc::channel();
        self.ares_channel.lock().unwrap().query_mx(name, move |result| {
            tx.send(result).unwrap();
        });
        rx.recv().unwrap()
    }

    // A blocking NAPTR query.
    pub fn query_naptr(&self, name: &str)
        -> Result<c_ares::NAPTRResults, c_ares::AresError> {
        let (tx, rx) = mpsc::channel();
        self.ares_channel.lock().unwrap().query_naptr(name, move |result| {
            tx.send(result).unwrap();
        });
        rx.recv().unwrap()
    }
}

impl Drop for Resolver {
    fn drop(&mut self) {
        // Shut down the event loop and wait for it to finish.
        self.event_loop_channel
            .send(CAresHandlerMessage::ShutDown)
            .ok()
            .expect("failed to shut down event loop");
       for handle in self.event_loop_handle.take() {
           handle.join().unwrap();
       }
    }
}

fn print_cname_result(result: Result<c_ares::CNameResults, c_ares::AresError>) {
    match result {
        Err(e) => {
            println!("CNAME lookup failed with error '{}'", e.description());
        }
        Ok(cname_results) => {
            println!("Successful CNAME lookup...");
            for cname_result in cname_results.aliases() {
                println!("{}", cname_result.alias());
            }
        }
    }
}

fn print_mx_results(result: Result<c_ares::MXResults, c_ares::AresError>) {
    match result {
        Err(e) => {
            println!("MX lookup failed with error '{}'", e.description());
        }
        Ok(mx_results) => {
            println!("Successful MX lookup...");
            for mx_result in &mx_results {
                println!(
                    "host {}, priority {}",
                    mx_result.host(),
                    mx_result.priority());
            }
        }
    }
}

fn print_naptr_results(
    result: Result<c_ares::NAPTRResults, c_ares::AresError>) {
    match result {
        Err(e) => {
            println!("NAPTR lookup failed with error '{}'", e.description());
        }
        Ok(naptr_results) => {
            println!("Successful NAPTR lookup...");
            for naptr_result in &naptr_results {
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

fn main() {
    // Create a Resolver.  Then make some requests.
    let resolver = Resolver::new();
    let result = resolver.query_cname("dimbleby.github.io");
    println!("");
    print_cname_result(result);

    let result = resolver.query_mx("gmail.com");
    println!("");
    print_mx_results(result);

    let result = resolver.query_naptr("4.3.2.1.5.5.5.0.0.8.1.e164.arpa");
    println!("");
    print_naptr_results(result);
}
