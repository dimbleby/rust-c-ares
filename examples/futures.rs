// Simple example using `Futures`.
extern crate c_ares;
extern crate eventual;

use std::sync::{mpsc, Arc, Mutex};
use eventual::{Future, Async};

// TODO - commonize with the other example(s).
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

struct Resolver {
    ares_channel: Arc<Mutex<c_ares::Channel>>,
}
impl Resolver {
    fn new() -> Resolver {
        // Dummy callback.
        //
        // Not used here as the `Future` explicitly calls `wait_channel` when
        // we need to get at the results.
        //
        // I'd prefer that this callback could call `process_fd` on the
        // underlying `c_ares_sys::ares_channel`, but given the callback is
        // passed to the `c_ares::Channel` contructor, that becomes tricky.
        let dummy_callback = move |_: i32, _: bool, _: bool| {};

        // Create a `c_ares::Channel`.
        let mut options = c_ares::Options::new();
        options
            //.set_flags(c_ares::flags::STAYOPEN | c_ares::flags::EDNS)
            .set_timeout(500)
            .set_tries(3);
        let ares_channel = c_ares::Channel::new(dummy_callback, options) // Cheating on the channel
            .ok()
            .expect("Failed to create channel");

        Resolver { ares_channel: Arc::new(Mutex::new(ares_channel)) }
    }

    fn a_query_as_future(&mut self, name: &str) -> Future<Result<c_ares::AResults, c_ares::AresError>, ()> {
        // Make the query.
        let (tx, rx) = mpsc::channel();
        let mut channel = self.ares_channel.lock().unwrap();

        channel.query_a(name, move |results| {
            // Send the results when they arrive.
            tx.send(results).unwrap();
        });
        
        // Return a `Future` that will eventually get the result.
        let channel_clone = self.ares_channel.clone();
        Future::spawn(move || {
            loop {
                // Wait until we have a result, kicking the channel if not.
                match rx.try_recv() {
                    Ok(response) => return response,
                    _ => channel_clone.lock().unwrap().wait_channel(),
                }
            }
        })
    }
}

fn main() {
    // Perform a query, getting the result as a future.
    let mut resolver = Resolver::new();
    let results_future = resolver.a_query_as_future("apple.com");

    // Do some other stuff here while we wait
    // ...

    // Wait for and print the results
    let results = results_future
        .await()
        .ok()
        .expect("Future failed to complete");
    print_a_results(results);
}
