// A variation on event-loop.rs.
//
// Here we:
//
// - Have the event loop be run by a `Resolver`, hiding away the event loop details from the writer
// of `main()`.
//
// - Transform the callback-based c-ares interface into a futures-style.
//
// This example is fleshed out in the
// [c-ares-resolver](https://github.com/dimbleby/c-ares-resolver) crate.
#[cfg(unix)]
mod example {
    extern crate c_ares;
    extern crate futures;
    extern crate mio;
    extern crate mio_extras;
    extern crate tokio_current_thread as current_thread;

    use std::collections::HashSet;
    use std::error::Error;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    use self::futures::future::lazy;
    use self::futures::Future;

    // The EventLoop will set up a mio::Poll and use it to wait for the following:
    //
    // - messages telling it which file descriptors it should be interested in.  These file
    // descriptors are then registered (or deregistered) with the mio::Poll as required.
    //
    // - events telling it that something has happened on one of these file descriptors.  When
    // this happens, it tells the c_ares::Channel about it.
    //
    // - a message telling it to shut down.
    struct EventLoop {
        poll: mio::Poll,
        msg_channel: mio_extras::channel::Receiver<Message>,
        tracked_fds: HashSet<c_ares::Socket>,
        ares_channel: Arc<Mutex<c_ares::Channel>>,
        quit: bool,
    }

    // Messages for the event loop.
    #[derive(Debug)]
    enum Message {
        // 'Notify me when this file descriptor becomes readable, or writable'.  The first bool is
        // for 'readable' and the second is for 'writable'.  It's allowed to set both of these - or
        // neither, meaning 'I am no longer interested in this file descriptor'.
        RegisterInterest(c_ares::Socket, bool, bool),

        // 'Shut down'.
        ShutDown,
    }

    // A token identifying that the message channel has become available for reading.
    //
    // We use Token(fd) for file descriptors, so this relies on zero not being a valid file
    // descriptor for c-ares to use.  Zero is stdin, so that's true.
    const CHANNEL: mio::Token = mio::Token(0);

    impl EventLoop {
        // Create a new event loop.
        pub fn new(
            ares_channel: Arc<Mutex<c_ares::Channel>>,
            rx: mio_extras::channel::Receiver<Message>,
        ) -> Self {
            let poll = mio::Poll::new().expect("Failed to create poll");
            poll.register(&rx, CHANNEL, mio::Ready::readable(), mio::PollOpt::edge())
                .expect("failed to register channel with poll");

            EventLoop {
                poll,
                msg_channel: rx,
                tracked_fds: HashSet::<c_ares::Socket>::new(),
                ares_channel,
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
                let results = self
                    .poll
                    .poll(&mut events, Some(timeout))
                    .expect("poll failed");

                // Process whatever happened.
                match results {
                    0 => {
                        // No events - must be a timeout.  Tell c-ares about it.
                        self.ares_channel
                            .lock()
                            .unwrap()
                            .process_fd(c_ares::SOCKET_BAD, c_ares::SOCKET_BAD);
                    }
                    _ => {
                        // Process events.  One of them might have asked us to quit.
                        for event in &events {
                            self.handle_event(&event);
                            if self.quit {
                                return;
                            }
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
                }

                mio::Token(fd) => {
                    // Sockets became readable or writable - tell c-ares.
                    let rfd = if event.readiness().is_readable() {
                        fd as c_ares::Socket
                    } else {
                        c_ares::SOCKET_BAD
                    };
                    let wfd = if event.readiness().is_writable() {
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
                            let mut interest = mio::Ready::empty();
                            if readable {
                                interest.insert(mio::Ready::readable())
                            }
                            if writable {
                                interest.insert(mio::Ready::writable())
                            }
                            let register_result = if !self.tracked_fds.insert(fd) {
                                self.poll
                                    .reregister(&efd, token, interest, mio::PollOpt::level())
                            } else {
                                self.poll
                                    .register(&efd, token, interest, mio::PollOpt::level())
                            };
                            register_result.expect("failed to register interest");
                        }
                    }

                    Ok(Message::ShutDown) => {
                        // Instruction to shut down.
                        self.quit = true;
                        break;
                    }

                    // No more instructions.
                    Err(_) => break,
                }
            }
        }
    }

    // The type of future returned by methods on the Resolver.
    struct CAresFuture<T> {
        inner: futures::sync::oneshot::Receiver<c_ares::Result<T>>,
    }

    impl<T> CAresFuture<T> {
        fn new(promise: futures::sync::oneshot::Receiver<c_ares::Result<T>>) -> Self {
            CAresFuture { inner: promise }
        }
    }

    impl<T> Future for CAresFuture<T> {
        type Item = T;
        type Error = c_ares::Error;

        fn poll(&mut self) -> futures::Poll<Self::Item, Self::Error> {
            match self.inner.poll() {
                Ok(futures::Async::NotReady) => Ok(futures::Async::NotReady),
                Err(_) => Err(c_ares::Error::ECANCELLED),
                Ok(futures::Async::Ready(res)) => match res {
                    Ok(r) => Ok(futures::Async::Ready(r)),
                    Err(e) => Err(e),
                },
            }
        }
    }

    // The Resolver is the interface by which users make DNS queries.
    struct Resolver {
        ares_channel: Arc<Mutex<c_ares::Channel>>,
        event_loop_channel: mio_extras::channel::Sender<Message>,
        event_loop_handle: Option<thread::JoinHandle<()>>,
    }

    impl Resolver {
        // Create a new Resolver.
        pub fn new() -> Self {
            // Whenever c-ares tells us what to do with a file descriptor, we'll send that request
            // along, in a message to the event loop thread.
            let (tx, rx) = mio_extras::channel::channel();
            let tx_clone = tx.clone();
            let sock_callback = move |fd: c_ares::Socket, readable: bool, writable: bool| {
                let _ = tx_clone.send(Message::RegisterInterest(fd, readable, writable));
            };

            // Create a c_ares::Channel.
            let mut options = c_ares::Options::new();
            options
                .set_socket_state_callback(sock_callback)
                .set_flags(c_ares::Flags::STAYOPEN | c_ares::Flags::EDNS)
                .set_timeout(500)
                .set_tries(3);
            let mut ares_channel =
                c_ares::Channel::with_options(options).expect("Failed to create channel");
            ares_channel
                .set_servers(&["8.8.8.8"])
                .expect("Failed to set servers");
            let locked_channel = Arc::new(Mutex::new(ares_channel));

            // Create and run the event loop.
            let channel_clone = Arc::clone(&locked_channel);
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
        pub fn query_cname(
            &self,
            name: &str,
        ) -> impl Future<Item = c_ares::CNameResults, Error = c_ares::Error> {
            let (c, p) = futures::oneshot();
            self.ares_channel
                .lock()
                .unwrap()
                .query_cname(name, move |result| {
                    let _ = c.send(result);
                });
            CAresFuture::new(p)
        }

        // An MX query.  Returns a future that will resolve to hold the result.
        pub fn query_mx(
            &self,
            name: &str,
        ) -> impl Future<Item = c_ares::MXResults, Error = c_ares::Error> {
            let (c, p) = futures::oneshot();
            self.ares_channel
                .lock()
                .unwrap()
                .query_mx(name, move |result| {
                    let _ = c.send(result);
                });
            CAresFuture::new(p)
        }

        // A NAPTR query.  Returns a future that will resolve to hold the result.
        pub fn query_naptr(
            &self,
            name: &str,
        ) -> impl Future<Item = c_ares::NAPTRResults, Error = c_ares::Error> {
            let (c, p) = futures::oneshot();
            self.ares_channel
                .lock()
                .unwrap()
                .query_naptr(name, move |result| {
                    let _ = c.send(result);
                });
            CAresFuture::new(p)
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

    pub fn main() {
        // Create a Resolver, and some queries.
        let resolver = Resolver::new();
        let cname_query = resolver
            .query_cname("dimbleby.github.com")
            .map_err(|e| println!("CNAME lookup failed with error '{}'", e.description()))
            .map(|results| {
                println!();
                println!("Successful CNAME lookup...");
                println!("Hostname: {}", results.hostname().to_string_lossy());
                for alias in results.aliases() {
                    println!("Alias: {}", alias.to_string_lossy());
                }
                println!();
            });

        let mx_query = resolver
            .query_mx("gmail.com")
            .map_err(|e| println!("MX lookup failed with error '{}'", e.description()))
            .map(|results| {
                println!();
                println!("Successful MX lookup...");
                for result in &results {
                    println!(
                        "host {}, priority {}",
                        result.host().to_string_lossy(),
                        result.priority()
                    );
                }
                println!();
            });

        let naptr_query = resolver
            .query_naptr("apple.com")
            .map_err(|e| println!("NAPTR lookup failed with error '{}'", e.description()))
            .map(|results| {
                println!();
                println!("Successful NAPTR lookup...");
                for result in &results {
                    println!("flags: {}", result.flags().to_string_lossy());
                    println!("service name: {}", result.service_name().to_string_lossy());
                    println!("regular expression: {}", result.reg_exp().to_string_lossy());
                    println!(
                        "replacement pattern: {}",
                        result.replacement_pattern().to_string_lossy()
                    );
                    println!("order: {}", result.order());
                    println!("preference: {}", result.preference());
                }
                println!();
            });

        // Execute the queries.
        current_thread::block_on_all(lazy(|| {
            current_thread::spawn(cname_query);
            current_thread::spawn(mx_query);
            current_thread::spawn(naptr_query);
            Ok::<(), ()>(())
        }))
        .unwrap();
    }
}

#[cfg(unix)]
pub fn main() {
    example::main();
}

#[cfg(not(unix))]
pub fn main() {
    println!("this example is not supported on this platform");
}
