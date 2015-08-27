// This example uses the callback mechanism to find out which file descriptors
// c-ares cares about.  This is a good fit for an event loop; here we use mio.
extern crate c_ares;
extern crate mio;

use std::collections::HashSet;
use std::error::Error;
use std::net::{
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
    SocketAddrV4,
};
use std::sync::mpsc;
use std::thread;

// Messages for the event loop.
enum CAresHandlerMessage {
    // 'Notify me when this file descriptor becomes readable, or writable'
    // The first bool is for 'readable' and the second is for 'writable'.  It's
    // allowed to set both of these - or neither, meaning 'I am no longer
    // interested in this file descriptor'.
    RegisterInterest(c_ares::Socket, bool, bool),

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
    tracked_fds: HashSet<c_ares::Socket>,
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
        let fd = token.as_usize() as c_ares::Socket;
        let read_fd = if events.is_readable() {
            fd
        } else {
            c_ares::SOCKET_BAD
        };
        let write_fd = if events.is_writable() {
            fd
        } else {
            c_ares::SOCKET_BAD
        };
        self.ares_channel.process_fd(read_fd, write_fd);
    }

    // Process received messages.  Either:
    // - we're asked to register interest (or non-interest) in a file
    // descriptor
    // - we're asked to shut down the event loop.
    #[cfg(unix)]
    fn notify(
        &mut self,
        event_loop:&mut mio::EventLoop<CAresEventHandler>,
        msg: Self::Message) {
        match msg {
            CAresHandlerMessage::RegisterInterest(fd, read, write) => {
                let efd = mio::unix::EventedFd(&fd);
                if !read && !write {
                    self.tracked_fds.remove(&fd);
                    event_loop
                        .deregister(&efd)
                        .ok()
                        .expect("failed to deregister interest");
                } else {
                    let mut interest = mio::EventSet::none();
                    if read {
                        interest = interest | mio::EventSet::readable();
                    }
                    if write {
                        interest = interest | mio::EventSet::writable();
                    }
                    let token = mio::Token(fd as usize);
                    let register_result = if !self.tracked_fds.insert(fd) {
                        event_loop
                            .reregister(
                                &efd,
                                token,
                                interest,
                                mio::PollOpt::edge())
                    } else {
                        event_loop
                            .register_opt(
                                &efd,
                                token,
                                interest,
                                mio::PollOpt::edge())
                    };
                    register_result.ok().expect("failed to register interest");
                }
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
        self.ares_channel.process_fd(c_ares::SOCKET_BAD, c_ares::SOCKET_BAD);
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

fn print_host_results(result: Result<c_ares::HostResults, c_ares::AresError>) {
    match result {
        Err(e) => {
            println!("Host lookup failed with error '{}'", e.description());
        }
        Ok(host_results) => {
            println!("Successful host lookup...");
            println!("Hostname: {}", host_results.hostname());
            for alias in host_results.aliases() {
                println!("Alias: {}", alias.alias());
            }
            for address in host_results.addresses() {
                match address.ip_address() {
                    c_ares::IpAddr::V4(v4) => println!("IPv4: {:}", v4),
                    c_ares::IpAddr::V6(v6) => println!("IPv6: {:}", v6),
                }
            }
        }
    }
}

fn main() {
    if cfg!(windows) {
        println!("mio isn't quite ready for Windows yet...");
        return;
    }

    // Create an event loop.
    let mut event_loop = mio::EventLoop::new()
        .ok()
        .expect("failed to create event loop");
    let event_loop_channel = event_loop.channel();

    // Socket state callback for the c_ares::Channel will be to kick the event
    // loop.
    let event_loop_channel_clone = event_loop_channel.clone();
    let sock_callback =
        move |fd: c_ares::Socket, readable: bool, writable: bool| {
        let _ = event_loop_channel_clone
            .send(
                CAresHandlerMessage::RegisterInterest(fd, readable, writable));
    };

    // Create a c_ares::Channel.
    let mut options = c_ares::Options::new();
    options
        .set_socket_state_callback(sock_callback)
        .set_flags(c_ares::flags::STAYOPEN | c_ares::flags::EDNS)
        .set_timeout(500)
        .set_tries(3);
    let mut ares_channel = c_ares::Channel::new(options)
        .ok()
        .expect("Failed to create channel");

    // Set up some queries.
    let (results_tx, results_rx) = mpsc::channel();
    let tx = results_tx.clone();
    ares_channel.get_host_by_name(
        "google.com",
        c_ares::AddressFamily::INET,
        move |result| {
            println!("");
            print_host_results(result);
            tx.send(()).unwrap()
        }
    );

    let tx = results_tx.clone();
    let ipv4 = c_ares::IpAddr::V4(Ipv4Addr::new(216, 58, 208, 78));
    ares_channel.get_host_by_address(&ipv4, move |results| {
        println!("");
        print_host_results(results);
        tx.send(()).unwrap()
    });

    let tx = results_tx.clone();
    let ipv6 = c_ares::IpAddr::V6(
        Ipv6Addr::new(0x2a00, 0x1450, 0x4009, 0x80a, 0, 0, 0, 0x200e));
    ares_channel.get_host_by_address(&ipv6, move |results| {
        println!("");
        print_host_results(results);
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
    for _ in 0..3 {
        results_rx.recv().unwrap();
    }

    // Shut down the event loop and wait for it to finish.
    event_loop_channel
        .send(CAresHandlerMessage::ShutDown)
        .ok()
        .expect("failed to shut down event loop");
    handle.join().unwrap();
}
