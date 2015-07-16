extern crate c_ares;
extern crate mio;

use std::collections::HashSet;
use std::mem;
use std::os::unix::io;
use std::sync::mpsc;
use std::thread;

enum CAresHandlerMessage {
    RegisterInterest(io::RawFd, bool, bool),
    ShutDown,
}

struct CAresEventHandler {
    ares_channel: c_ares::Channel,
    tracked_fds: HashSet<io::RawFd>,
}

impl mio::Handler for CAresEventHandler {
    type Timeout = ();
    type Message = CAresHandlerMessage;

    fn readable(
        &mut self, 
        _event_loop: &mut mio::EventLoop<CAresEventHandler>,
        token: mio::Token,
        _read_hint: mio::ReadHint) {
        let fd = token.as_usize() as io::RawFd;
        self.ares_channel.process_fd(fd, c_ares::INVALID_FD);
    }

    fn writable(
        &mut self,
        _event_loop: &mut mio::EventLoop<CAresEventHandler>,
        token: mio::Token) {
        let fd = token.as_usize() as io::RawFd;
        self.ares_channel.process_fd(c_ares::INVALID_FD, fd);
    }

    fn notify(
        &mut self,
        event_loop:&mut mio::EventLoop<CAresEventHandler>,
        msg: Self::Message) {
        match msg {
            CAresHandlerMessage::RegisterInterest(fd, readable, writable) => {
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

            CAresHandlerMessage::ShutDown => event_loop.shutdown(),
        }
    }

    fn timeout(
        &mut self,
        event_loop: &mut mio::EventLoop<CAresEventHandler>,
        _timeout: Self::Timeout) {
        self.ares_channel.process_fd(c_ares::INVALID_FD, c_ares::INVALID_FD);
        event_loop.timeout_ms((), 500).unwrap();
    }
}

impl CAresEventHandler {
    fn new(ares_channel: c_ares::Channel) -> CAresEventHandler {
        CAresEventHandler {
            ares_channel: ares_channel,
            tracked_fds: HashSet::new(),
        }
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
    // Create an event loop, and a c_ares::Channel.
    let mut event_loop = mio::EventLoop::new()
        .ok()
        .expect("failed to create event loop");
    let event_loop_channel = event_loop.channel();
    let ev_channel_clone = event_loop_channel.clone();
    let sock_callback = move |fd: io::RawFd, readable: bool, writable: bool| {
        ev_channel_clone
            .send(CAresHandlerMessage::RegisterInterest(fd, readable, writable))
            .ok()
            .expect("Failed to send RegisterInterest");
    };
    let mut ares_channel = c_ares::Channel::new(sock_callback)
        .ok()
        .expect("Failed to create channel");

    // Set up a couple of queries.
    let (results_tx, results_rx) = mpsc::channel();
    let tx = results_tx.clone();
    ares_channel.query_a("apple.com", move |result| {
        print_a_result(result);
        tx.send(()).unwrap()
    });

    let tx = results_tx.clone();
    ares_channel.query_aaaa("google.com", move |result| {
        print_aaaa_result(result);
        tx.send(()).unwrap()
    });

    // Kick off the event loop.
    event_loop.timeout_ms((), 500).unwrap();
    let mut event_handler = CAresEventHandler::new(ares_channel);
    let handle = thread::spawn(move || {
        event_loop
            .run(&mut event_handler)
            .ok()
            .expect("failed to run event loop")
    });

    // Wait for results to roll in.
    for _ in 0..2 {
        results_rx.recv().unwrap();
    }

    // Shut down event loop.
    event_loop_channel
        .send(CAresHandlerMessage::ShutDown)
        .ok()
        .expect("failed to shut down event loop");
    handle.join().unwrap();
}
