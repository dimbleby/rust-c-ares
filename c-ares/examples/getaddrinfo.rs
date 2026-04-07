// This example uses the c-ares built-in event thread to resolve a hostname via
// `get_addrinfo()`, initiating a host query by name and service.

#[cfg(cares1_28)]
mod inner {
    use std::time::Duration;

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        if !c_ares::thread_safety() {
            eprintln!("c-ares was not built with thread safety; cannot use event thread");
            return Ok(());
        }

        #[cfg(windows)]
        let _ = std::net::UdpSocket::bind("127.0.0.1:0");

        let domain = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "google.com".to_string());

        // Enable the built-in event thread so c-ares manages its own I/O.
        let mut options = c_ares::Options::new();
        options
            .set_flags(c_ares::Flags::STAYOPEN)
            .set_timeout(Duration::from_millis(500))
            .set_tries(3)
            .set_event_thread(c_ares::EventSys::Default);

        let mut channel = c_ares::Channel::with_options(options)?;
        channel.set_servers(&["8.8.8.8"])?;

        // Build hints requesting both IPv4 and IPv6 with canonical name.
        let hints = c_ares::AddrInfoHints {
            flags: c_ares::AddrInfoFlags::CANONNAME,
            family: None, // AF_UNSPEC — return both v4 and v6
            ..Default::default()
        };

        channel.get_addrinfo(&domain, None, &hints, move |result| match result {
            Ok(info) => {
                if let Some(name) = info.name() {
                    println!("Canonical name: {name}");
                }

                for cname in info.cnames() {
                    println!("  CNAME: {}", cname.name());
                }

                for node in info.nodes() {
                    if let Some(addr) = node.ip_addr() {
                        println!("  {} (TTL {}s)", addr, node.ttl());
                    }
                }
            }
            Err(e) => eprintln!("get_addrinfo failed: {e}"),
        });

        // Wait for the query to complete.
        channel.queue_wait_empty(Some(Duration::from_secs(5)))?;

        Ok(())
    }
}

#[cfg(cares1_28)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    inner::run()
}

#[cfg(not(cares1_28))]
fn main() {
    eprintln!("This example requires c-ares >= 1.28");
}
