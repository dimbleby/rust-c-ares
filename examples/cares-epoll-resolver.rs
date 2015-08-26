// A variation on cares-epoll.rs
//
// Here we hide the use of epoll() behind a `Resolver` object.  We also
// transform the asynchronous c-ares interface into a synchronous one, by
// using a std::sync::mpsc::channel.
extern crate c_ares;
extern crate nix;

use nix::sys::epoll::{
    epoll_create,
    epoll_ctl,
    epoll_wait,
    EpollEvent,
    EpollEventKind,
    EpollOp,
    EPOLLIN,
    EPOLLOUT,
};
use std::collections::HashSet;
use std::error::Error;
use std::os::unix::io;
use std::sync::{
    Arc,
    Condvar,
    Mutex,
    mpsc,
};
use std::thread;

struct Resolver {
    ares_channel: Arc<Mutex<c_ares::Channel>>,
    keep_going: Arc<(Mutex<bool>, Condvar)>,
    fd_handle: Option<thread::JoinHandle<()>>,
}

// A thread that keeps going processing file descriptors for c-ares, until it
// is asked to stop.
fn fd_handling_thread(
    ares_channel: Arc<Mutex<c_ares::Channel>>,
    keep_going: Arc<(Mutex<bool>, Condvar)>) {
    let (ref lock, ref cvar) = *keep_going;
    let mut carry_on = lock.lock().unwrap();
    while *carry_on {
        process_ares_fds(ares_channel.clone());
        carry_on = cvar.wait(carry_on).unwrap();
    }
}

// Process file descriptors for c-ares, while it wants us to do so.
fn process_ares_fds(ares_channel: Arc<Mutex<c_ares::Channel>>) {
    // Create an epoll file descriptor so that we can listen for events.
    let epoll = epoll_create().ok().expect("Failed to create epoll");
    let mut tracked_fds = HashSet::<io::RawFd>::new();
    loop {
        // Ask c-ares what file descriptors we should be listening on, and map
        // those requests onto the epoll file descriptor.
        let mut active = false;
        let sockets = ares_channel.lock().unwrap().get_sock();
        for (fd, readable, writable) in &sockets {
            let mut interest = EpollEventKind::empty();
            if readable { interest = interest | EPOLLIN; }
            if writable { interest = interest | EPOLLOUT; }
            let event = EpollEvent {
                events: interest,
                data: fd as u64,
            };
            let op = if tracked_fds.insert(fd) {
                EpollOp::EpollCtlAdd
            } else {
                EpollOp::EpollCtlMod
            };
            epoll_ctl(epoll, op, fd, &event).ok().expect("epoll_ctl failed");
            active = true;
        }
        if !active { break }

        // Wait for something to happen.
        let empty_event = EpollEvent {
            events: EpollEventKind::empty(),
            data: 0,
        };
        let mut events = [empty_event; 2];
        let results = epoll_wait(epoll, &mut events, 500)
            .ok()
            .expect("epoll_wait failed");

        // Process whatever happened.
        match results {
            0 => {
                // No events - must be a timeout.  Tell c-ares about it.
                ares_channel.lock().unwrap().process_fd(
                    c_ares::SOCKET_BAD,
                    c_ares::SOCKET_BAD);
            },
            n => {
                // Sockets became readable or writable.  Tell c-ares about it.
                for event in &events[0..n] {
                    let active_fd = event.data as io::RawFd;
                    let readable_fd = if (event.events & EPOLLIN).is_empty() {
                        c_ares::SOCKET_BAD
                    } else {
                        active_fd
                    };
                    let writable_fd = if (event.events & EPOLLOUT).is_empty() {
                        c_ares::SOCKET_BAD
                    } else {
                        active_fd
                    };
                    ares_channel
                        .lock()
                        .unwrap()
                        .process_fd(readable_fd, writable_fd);
                }
            }
        }
    }
}

impl Resolver {
    // Create a new Resolver
    pub fn new() -> Resolver {
        // Create a c_ares::Channel.
        let mut options = c_ares::Options::new();
        options
            .set_flags(c_ares::flags::STAYOPEN)
            .set_timeout(500)
            .set_tries(3);
        let ares_channel = c_ares::Channel::new(options)
            .ok()
            .expect("Failed to create channel");
        let locked_channel = Arc::new(Mutex::new(ares_channel));

        // Create a thread to handle file descriptors.
        let keep_going = Arc::new((Mutex::new(true), Condvar::new()));
        let channel_clone = locked_channel.clone();
        let keep_going_clone = keep_going.clone();
        let fd_handle = thread::spawn(move || {
            fd_handling_thread(channel_clone, keep_going_clone)
        });

        Resolver {
            ares_channel: locked_channel,
            keep_going: keep_going,
            fd_handle: Some(fd_handle),
        }
    }

    fn wake_fd_thread(&self) {
        let (ref _lock, ref cvar) = *self.keep_going;
        cvar.notify_one();
    }

    // A blocking NS query.  Achieve this by having the callback send the
    // result to a std::sync::mpsc::channel, and waiting on that channel.
    pub fn query_ns(&self, name: &str)
        -> Result<c_ares::NSResults, c_ares::AresError> {
        let (tx, rx) = mpsc::channel();
        self.ares_channel.lock().unwrap().query_ns(name, move |result| {
            tx.send(result).unwrap();
        });
        self.wake_fd_thread();
        rx.recv().unwrap()
    }

    // A blocking PTR query.
    pub fn query_ptr(&self, name: &str)
        -> Result<c_ares::PTRResults, c_ares::AresError> {
        let (tx, rx) = mpsc::channel();
        self.ares_channel.lock().unwrap().query_ptr(name, move |result| {
            tx.send(result).unwrap();
        });
        self.wake_fd_thread();
        rx.recv().unwrap()
    }

    // A blocking TXT query.
    pub fn query_txt(&self, name: &str)
        -> Result<c_ares::TXTResults, c_ares::AresError> {
        let (tx, rx) = mpsc::channel();
        self.ares_channel.lock().unwrap().query_txt(name, move |result| {
            tx.send(result).unwrap();
        });
        self.wake_fd_thread();
        rx.recv().unwrap()
    }
}

impl Drop for Resolver {
    fn drop(&mut self) {
        // Kick the file descriptor thread to stop.
        let (ref lock, ref cvar) = *self.keep_going;
        {
            let mut carry_on = lock.lock().unwrap();
            *carry_on = false;
        }
        cvar.notify_one();

        // Wait for it to do so.
        for handle in self.fd_handle.take() {
            handle.join().unwrap();
        }
    }
}

fn print_ns_results(result: Result<c_ares::NSResults, c_ares::AresError>) {
    match result {
        Err(e) => {
            println!("NS lookup failed with error '{}'", e.description());
        }
        Ok(ns_results) => {
            println!("Successful NS lookup...");
            for ns_result in ns_results.aliases() {
                println!("{}", ns_result.alias());
            }
        }
    }
}

fn print_ptr_results(result: Result<c_ares::PTRResults, c_ares::AresError>) {
    match result {
        Err(e) => {
            println!("PTR lookup failed with error '{}'", e.description());
        }
        Ok(ptr_results) => {
            println!("Successful PTR lookup...");
            for ptr_result in ptr_results.aliases() {
                println!("{}", ptr_result.alias());
            }
        }
    }
}

fn print_txt_results(result: Result<c_ares::TXTResults, c_ares::AresError>) {
    match result {
        Err(e) => {
            println!("TXT lookup failed with error '{}'", e.description());
        }
        Ok(txt_results) => {
            println!("Successful TXT lookup...");
            for txt_result in &txt_results {
                println!("{}", txt_result.text());
            }
        }
    }
}

fn main() {
    // Create a Resolver.  Then make some requests.
    let resolver = Resolver::new();
    let result = resolver.query_ns("google.com");
    println!("");
    print_ns_results(result);

    let result = resolver.query_ptr("14.210.58.216.in-addr.arpa");
    println!("");
    print_ptr_results(result);

    let result = resolver.query_txt("google.com");
    println!("");
    print_txt_results(result);
}
