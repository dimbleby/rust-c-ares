// This example drives c-ares using an mio::EventLoop.
extern crate c_ares;
extern crate mio;

use std::collections::HashSet;
use std::mem;
use std::os::unix::io;
use std::sync::mpsc;
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
    // Since the event handler owns the Channel, it's tricky to submit further
    // queries once the event loop is running.  If you want to do that,
    // either:
    //
    // -  share the Channel by using an Arc<Mutex<c_ares::Channel>>, OR
    // -  send requests to the event handler as messages, and have it make the
    //    queries
    ares_channel: c_ares::Channel,
    tracked_fds: HashSet<io::RawFd>,
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
        let read_fd = if events.is_readable() { fd } else { c_ares::INVALID_FD };
        let write_fd = if events.is_writable() { fd } else { c_ares::INVALID_FD };
        self.ares_channel.process_fd(read_fd, write_fd);
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
                                mio::PollOpt::level())
                    } else {
                        event_loop
                            .register_opt(
                                &io,
                                token,
                                interest,
                                mio::PollOpt::level())
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

fn print_a_results(result: Result<c_ares::AResults, c_ares::AresError>) {
    println!("");
    match result {
        Err(e) => {
            let err_string = c_ares::str_error(e);
            println!("A lookup failed with error '{}'", err_string);
        }
        Ok(a_results) => {
            println!("Successful A lookup...");
            println!("Hostname: {}", a_results.hostname());
            for a_result in &a_results {
                println!("{:}", a_result.ipv4_addr());
            }
        }
    }
}

fn print_aaaa_results(result: Result<c_ares::AAAAResults, c_ares::AresError>) {
    println!("");
    match result {
        Err(e) => {
            let err_string = c_ares::str_error(e);
            println!("AAAA lookup failed with error '{}'", err_string);
        }
        Ok(aaaa_results) => {
            println!("Successful AAAA lookup...");
            println!("Hostname: {}", aaaa_results.hostname());
            for aaaa_result in &aaaa_results {
                println!("{:}", aaaa_result.ipv6_addr());
            }
        }
    }
}

fn print_cname_result(result: Result<c_ares::CNameResult, c_ares::AresError>) {
    println!("");
    match result {
        Err(e) => {
            let err_string = c_ares::str_error(e);
            println!("CNAME lookup failed with error '{}'", err_string);
        }
        Ok(cname_result) => {
            println!("Successful CNAME lookup...");
            println!("{}", cname_result.cname());
        }
    }
}

fn print_mx_results(result: Result<c_ares::MXResults, c_ares::AresError>) {
    println!("");
    match result {
        Err(e) => {
            let err_string = c_ares::str_error(e);
            println!("MX lookup failed with error '{}'", err_string);
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

fn print_ns_results(result: Result<c_ares::NSResults, c_ares::AresError>) {
    println!("");
    match result {
        Err(e) => {
            let err_string = c_ares::str_error(e);
            println!("NS lookup failed with error '{}'", err_string);
        }
        Ok(ns_results) => {
            println!("Successful NS lookup...");
            for ns_result in &ns_results {
                println!("{:}", ns_result.name_server());
            }
        }
    }
}

fn print_ptr_results(result: Result<c_ares::PTRResults, c_ares::AresError>) {
    println!("");
    match result {
        Err(e) => {
            let err_string = c_ares::str_error(e);
            println!("PTR lookup failed with error '{}'", err_string);
        }
        Ok(ptr_results) => {
            println!("Successful PTR lookup...");
            for ptr_result in &ptr_results {
                println!("{:}", ptr_result.cname());
            }
        }
    }
}

fn print_txt_results(result: Result<c_ares::TXTResults, c_ares::AresError>) {
    println!("");
    match result {
        Err(e) => {
            let err_string = c_ares::str_error(e);
            println!("TXT lookup failed with error '{}'", err_string);
        }
        Ok(txt_results) => {
            println!("Successful TXT lookup...");
            for txt_result in &txt_results {
                println!("{:}", txt_result.text());
            }
        }
    }
}

fn print_soa_result(result: Result<c_ares::SOAResult, c_ares::AresError>) {
    println!("");
    match result {
        Err(e) => {
            let err_string = c_ares::str_error(e);
            println!("SOA lookup failed with error '{}'", err_string);
        }
        Ok(soa_result) => {
            println!("Successful SOA lookup...");
            println!("Name server: {}", soa_result.name_server());
            println!("Hostmaster: {}", soa_result.hostmaster());
            println!("Serial: {}", soa_result.serial());
            println!("Retry: {}", soa_result.retry());
            println!("Expire: {}", soa_result.expire());
            println!("Min TTL: {}", soa_result.min_ttl());
        }
    }
}

fn main() {
    // Create an event loop, and a c_ares::Channel.
    let mut event_loop = mio::EventLoop::new()
        .ok()
        .expect("failed to create event loop");
    let event_loop_channel = event_loop.channel();
    let event_loop_channel_clone = event_loop_channel.clone();
    let sock_callback = move |fd: io::RawFd, readable: bool, writable: bool| {
        event_loop_channel_clone
            .send(CAresHandlerMessage::RegisterInterest(fd, readable, writable))
            .ok()
            .expect("Failed to send RegisterInterest");
    };
    let mut options = c_ares::Options::new();
    options
        .set_flags(c_ares::flags::STAYOPEN | c_ares::flags::EDNS)
        .set_timeout(500)
        .set_tries(3);
    let mut ares_channel = c_ares::Channel::new(sock_callback, options)
        .ok()
        .expect("Failed to create channel");

    // Set up some queries.
    let (results_tx, results_rx) = mpsc::channel();
    let tx = results_tx.clone();
    ares_channel.query_a("apple.com", move |results| {
        print_a_results(results);
        tx.send(()).unwrap()
    });

    let tx = results_tx.clone();
    ares_channel.query_aaaa("google.com", move |results| {
        print_aaaa_results(results);
        tx.send(()).unwrap()
    });

    let tx = results_tx.clone();
    ares_channel.query_cname("dimbleby.github.io", move |result| {
        print_cname_result(result);
        tx.send(()).unwrap()
    });

    let tx = results_tx.clone();
    ares_channel.query_mx("gmail.com", move |results| {
        print_mx_results(results);
        tx.send(()).unwrap()
    });

    let tx = results_tx.clone();
    ares_channel.query_ns("google.com", move |results| {
        print_ns_results(results);
        tx.send(()).unwrap()
    });

    let tx = results_tx.clone();
    ares_channel.query_ptr("14.210.58.216.in-addr.arpa", move |results| {
        print_ptr_results(results);
        tx.send(()).unwrap()
    });

    let tx = results_tx.clone();
    ares_channel.query_txt("google.com", move |results| {
        print_txt_results(results);
        tx.send(()).unwrap()
    });

    let tx = results_tx.clone();
    ares_channel.query_soa("google.com", move |results| {
        print_soa_result(results);
        tx.send(()).unwrap()
    });

    // Set the first instance of the recurring timer on the event loop.
    event_loop.timeout_ms((), 500).unwrap();

    // Kick off the event loop.
    let mut event_handler = CAresEventHandler::new(ares_channel);
    let handle = thread::spawn(move || {
        event_loop
            .run(&mut event_handler)
            .ok()
            .expect("failed to run event loop")
    });

    // Wait for results to roll in.
    for _ in 0..8 {
        results_rx.recv().unwrap();
    }

    // Shut down the event loop and wait for it to finish.
    event_loop_channel
        .send(CAresHandlerMessage::ShutDown)
        .ok()
        .expect("failed to shut down event loop");
    handle.join().unwrap();
}
