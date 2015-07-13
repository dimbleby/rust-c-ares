extern crate c_ares;
extern crate mio;

use std::collections::HashSet;
use std::mem;
use std::os::unix::io;
use std::sync::mpsc;
use std::thread;

enum ResolverMessage {
    RegisterInterest(io::RawFd, bool, bool),
    ShutDown,
}

struct DNSResolver {
    ares_channel: c_ares::Channel,
    tracked_fds: HashSet<io::RawFd>,
}

impl mio::Handler for DNSResolver {
    type Timeout = usize;
    type Message = ResolverMessage;

    fn readable(
        &mut self, 
        _event_loop: &mut mio::EventLoop<DNSResolver>,
        token: mio::Token,
        _read_hint: mio::ReadHint) {
        let fd = token.as_usize() as io::RawFd;
        self.ares_channel.process_fd(fd, c_ares::SOCKET_BAD);
    }

    fn writable(
        &mut self,
        _event_loop: &mut mio::EventLoop<DNSResolver>,
        token: mio::Token) {
        let fd = token.as_usize() as io::RawFd;
        self.ares_channel.process_fd(c_ares::SOCKET_BAD, fd);
    }

    fn notify(
        &mut self,
        event_loop:&mut mio::EventLoop<DNSResolver>,
        msg: Self::Message) {
        match msg {
            ResolverMessage::RegisterInterest(fd, readable, writable) => {
                let io = mio::Io::new(fd);
                if !readable && !writable {
                    self.tracked_fds.remove(&fd);
                    event_loop
                        .deregister(&io)
                        .ok()
                        .expect("failed to deregister interest");
                } else {
                    let mut interest = mio::Interest::none();
                    if readable {
                        interest = interest | mio::Interest::readable();
                    }
                    if writable {
                        interest = interest | mio::Interest::writable();
                    }
                    let token = mio::Token(fd as usize);
                    let insert_result = if !self.tracked_fds.insert(fd) { 
                        event_loop
                            .reregister(
                                &io,
                                token,
                                interest,
                                mio::PollOpt::level())
                    } else {
                        event_loop
                            .register_opt(
                                &io,
                                token,
                                interest,
                                mio::PollOpt::level())
                    };
                    insert_result.ok().expect("failed to register interest");
                }

                // Don't close the file descriptor by dropping io.
                mem::forget(io);
            },

            ResolverMessage::ShutDown => event_loop.shutdown(),
        }
    }
}

impl DNSResolver {
    fn new<F>(callback: F) -> DNSResolver
        where F: FnOnce(io::RawFd, bool, bool) + 'static {
        let ares_channel = c_ares::Channel::new(callback)
            .ok()
            .expect("Failed to create channel");
        DNSResolver {
            ares_channel: ares_channel,
            tracked_fds: HashSet::new(),
        }
    }

    fn query_a<F>(&mut self, name: &str, callback: F)
        where F: FnOnce(Result<c_ares::AResult, c_ares::AresError>) + 'static {
        self.ares_channel.query_a(name, callback);
    }

    fn query_aaaa<F>(&mut self, name: &str, callback: F)
        where F: FnOnce(Result<c_ares::AAAAResult, c_ares::AresError>) + 'static {
        self.ares_channel.query_aaaa(name, callback);
    }
}

fn print_a_result(result: Result<c_ares::AResult, c_ares::AresError>) {
    match result {
        Err(e) => {
            let err_string = c_ares::str_error(e);
            println!("Lookup failed with error '{:}'", err_string);
        }
        Ok(result) => {
            println!("Successful lookup...");
            for addr in &result.ip_addrs {
                println!("{:}", addr);
            }
        }
    }
}

fn print_aaaa_result(result: Result<c_ares::AAAAResult, c_ares::AresError>) {
    match result {
        Err(e) => {
            let err_string = c_ares::str_error(e);
            println!("Lookup failed with error '{:}'", err_string);
        }
        Ok(result) => {
            println!("Successful lookup...");
            for addr in &result.ip_addrs {
                println!("{:}", addr);
            }
        }
    }
}

fn main() {
    // Create an event loop and a DNSResolver.
    let mut event_loop = mio::EventLoop::new()
        .ok()
        .expect("failed to create event loop");
    let event_loop_channel = event_loop.channel();
    let ev_channel_clone = event_loop_channel.clone();
    let sock_callback = move |fd: io::RawFd, readable: bool, writable: bool| {
        ev_channel_clone
            .send(ResolverMessage::RegisterInterest(fd, readable, writable))
            .ok()
            .expect("Failed to send RegisterInterest");
    };
    let mut resolver = DNSResolver::new(sock_callback);

    // Set up a couple of queries.
    let (results_tx, results_rx) = mpsc::channel();
    let tx = results_tx.clone();
    resolver.query_a("apple.com", move |result| {
        print_a_result(result);
        tx.send(()).unwrap()
    });

    let tx = results_tx.clone();
    resolver.query_aaaa("google.com", move |result| {
        print_aaaa_result(result);
        tx.send(()).unwrap()
    });

    // Kick off the event loop.
    thread::spawn(move || {
        event_loop
            .run(&mut resolver)
            .ok()
            .expect("failed to run event loop")
    });

    // Wait for results to roll in.
    for _ in 0..2 {
        results_rx.recv().unwrap();
    }

    // Shut down event loop.
    event_loop_channel
        .send(ResolverMessage::ShutDown)
        .ok()
        .expect("failed to shut down event loop");
}
