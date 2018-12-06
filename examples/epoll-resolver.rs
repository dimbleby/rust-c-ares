// A variation on epoll.rs
//
// Here we hide the use of epoll() behind a `Resolver` object.  We also transform the asynchronous
// c-ares interface into a synchronous one, by using a std::sync::mpsc::channel.
#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
extern crate nix;

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
mod example {
    extern crate c_ares;

    use nix::sys::epoll::{epoll_create, epoll_ctl, epoll_wait, EpollEvent, EpollFlags, EpollOp};
    use std::collections::HashSet;
    use std::error::Error;
    use std::str;
    use std::sync::{mpsc, Arc, Condvar, Mutex};
    use std::thread;

    struct Resolver {
        ares_channel: Arc<Mutex<c_ares::Channel>>,
        keep_going: Arc<(Mutex<bool>, Condvar)>,
        fd_handle: Option<thread::JoinHandle<()>>,
    }

    // A thread that keeps going processing file descriptors for c-ares, until it is asked to stop.
    fn fd_handling_thread(
        ares_channel: &Mutex<c_ares::Channel>,
        keep_going: &(Mutex<bool>, Condvar),
    ) {
        let (ref lock, ref cvar) = *keep_going;
        let mut carry_on = lock.lock().unwrap();
        while *carry_on {
            process_ares_fds(ares_channel);
            carry_on = cvar.wait(carry_on).unwrap();
        }
    }

    // Process file descriptors for c-ares, while it wants us to do so.
    fn process_ares_fds(ares_channel: &Mutex<c_ares::Channel>) {
        // Create an epoll file descriptor so that we can listen for events.
        let epoll = epoll_create().expect("Failed to create epoll");
        let mut tracked_fds = HashSet::<c_ares::Socket>::new();
        loop {
            // Ask c-ares what file descriptors we should be listening on, and map those requests
            // onto the epoll file descriptor.
            let mut active = false;
            let sockets = ares_channel.lock().unwrap().get_sock();
            for (fd, readable, writable) in &sockets {
                let mut interest = EpollFlags::empty();
                if readable {
                    interest |= EpollFlags::EPOLLIN;
                }
                if writable {
                    interest |= EpollFlags::EPOLLOUT;
                }
                let mut event = EpollEvent::new(interest, fd as u64);
                let op = if tracked_fds.insert(fd) {
                    EpollOp::EpollCtlAdd
                } else {
                    EpollOp::EpollCtlMod
                };
                epoll_ctl(epoll, op, fd, &mut event).expect("epoll_ctl failed");
                active = true;
            }
            if !active {
                break;
            }

            // Wait for something to happen.
            let empty_event = EpollEvent::new(EpollFlags::empty(), 0);
            let mut events = [empty_event; 2];
            let results = epoll_wait(epoll, &mut events, 500).expect("epoll_wait failed");

            // Process whatever happened.
            match results {
                0 => {
                    // No events - must be a timeout.  Tell c-ares about it.
                    ares_channel
                        .lock()
                        .unwrap()
                        .process_fd(c_ares::SOCKET_BAD, c_ares::SOCKET_BAD);
                }
                n => {
                    // Sockets became readable or writable.  Tell c-ares.
                    for event in &events[0..n] {
                        let active_fd = event.data() as c_ares::Socket;
                        let rfd = if (event.events() & EpollFlags::EPOLLIN).is_empty() {
                            c_ares::SOCKET_BAD
                        } else {
                            active_fd
                        };
                        let wfd = if (event.events() & EpollFlags::EPOLLOUT).is_empty() {
                            c_ares::SOCKET_BAD
                        } else {
                            active_fd
                        };
                        ares_channel.lock().unwrap().process_fd(rfd, wfd);
                    }
                }
            }
        }
    }

    impl Resolver {
        // Create a new Resolver
        pub fn new() -> Self {
            // Create a c_ares::Channel.
            let mut options = c_ares::Options::new();
            options
                .set_flags(c_ares::Flags::STAYOPEN)
                .set_timeout(500)
                .set_tries(3);
            let mut ares_channel =
                c_ares::Channel::with_options(options).expect("Failed to create channel");
            ares_channel
                .set_servers(&["8.8.8.8"])
                .expect("Failed to set servers");
            let locked_channel = Arc::new(Mutex::new(ares_channel));

            // Create a thread to handle file descriptors.
            #[allow(clippy::mutex_atomic)]
            let keep_going = Arc::new((Mutex::new(true), Condvar::new()));
            let fd_handle = thread::spawn({
                let locked_channel = Arc::clone(&locked_channel);
                let keep_going = Arc::clone(&keep_going);
                move || fd_handling_thread(&*locked_channel, &*keep_going)
            });

            Resolver {
                ares_channel: locked_channel,
                keep_going,
                fd_handle: Some(fd_handle),
            }
        }

        fn wake_fd_thread(&self) {
            let (ref _lock, ref cvar) = *self.keep_going;
            cvar.notify_one();
        }

        // A blocking NS query.  Achieve this by having the callback send the result to a
        // std::sync::mpsc::channel, and waiting on that channel.
        pub fn query_ns(&self, name: &str) -> c_ares::Result<c_ares::NSResults> {
            let (tx, rx) = mpsc::channel();
            self.ares_channel
                .lock()
                .unwrap()
                .query_ns(name, move |result| {
                    tx.send(result).unwrap();
                });
            self.wake_fd_thread();
            rx.recv().unwrap()
        }

        // A blocking PTR query.
        pub fn query_ptr(&self, name: &str) -> c_ares::Result<c_ares::PTRResults> {
            let (tx, rx) = mpsc::channel();
            self.ares_channel
                .lock()
                .unwrap()
                .query_ptr(name, move |result| {
                    tx.send(result).unwrap();
                });
            self.wake_fd_thread();
            rx.recv().unwrap()
        }

        // A blocking TXT query.
        pub fn query_txt(&self, name: &str) -> c_ares::Result<c_ares::TXTResults> {
            let (tx, rx) = mpsc::channel();
            self.ares_channel
                .lock()
                .unwrap()
                .query_txt(name, move |result| {
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
            if let Some(handle) = self.fd_handle.take() {
                handle.join().unwrap();
            }
        }
    }

    fn print_ns_results(result: &c_ares::Result<c_ares::NSResults>) {
        match *result {
            Err(ref e) => {
                println!("NS lookup failed with error '{}'", e.description());
            }
            Ok(ref ns_results) => {
                println!("Successful NS lookup...");
                for alias in ns_results.aliases() {
                    println!("{}", alias.to_string_lossy());
                }
            }
        }
    }

    fn print_ptr_results(result: &c_ares::Result<c_ares::PTRResults>) {
        match *result {
            Err(ref e) => {
                println!("PTR lookup failed with error '{}'", e.description());
            }
            Ok(ref ptr_results) => {
                println!("Successful PTR lookup...");
                for alias in ptr_results.aliases() {
                    println!("{}", alias.to_string_lossy());
                }
            }
        }
    }

    fn print_txt_results(result: &c_ares::Result<c_ares::TXTResults>) {
        match *result {
            Err(ref e) => {
                println!("TXT lookup failed with error '{}'", e.description());
            }
            Ok(ref txt_results) => {
                println!("Successful TXT lookup...");
                for txt_result in txt_results {
                    let text = str::from_utf8(txt_result.text()).unwrap_or("<binary>");
                    println!(
                        "record start: {}, text: {}",
                        txt_result.record_start(),
                        text
                    );
                }
            }
        }
    }

    pub fn main() {
        // Create a Resolver.  Then make some requests.
        let resolver = Resolver::new();
        let result = resolver.query_ns("google.com");
        println!();
        print_ns_results(&result);

        let result = resolver.query_ptr("14.210.58.216.in-addr.arpa");
        println!();
        print_ptr_results(&result);

        let result = resolver.query_txt("google.com");
        println!();
        print_txt_results(&result);
    }
}

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
pub fn main() {
    example::main();
}

#[cfg(not(all(unix, any(target_os = "linux", target_os = "android"))))]
pub fn main() {
    println!("this example is not supported on this platform");
}
