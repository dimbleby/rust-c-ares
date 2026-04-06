// This example uses the c-ares built-in event thread and the DnsRecord API to perform a DNS lookup
// without an application-managed event loop.

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

        // Build a DNS query.
        let mut query = c_ares::DnsRecord::new(
            0,
            c_ares::DnsFlags::RD,
            c_ares::DnsOpcode::Query,
            c_ares::DnsRcode::NoError,
        )?;
        query.query_add(&domain, c_ares::DnsRecordType::A, c_ares::DnsCls::IN)?;

        // Send the query.  The callback receives the parsed DnsRecord response.
        channel.send_dnsrec(&query, move |result| match result {
            Ok(record) => {
                if record.rr_count(c_ares::DnsSection::Answer) == 0 {
                    eprintln!("No answers for {domain} ({})", record.rcode());
                } else {
                    for rr in record.rrs(c_ares::DnsSection::Answer) {
                        if let Some(addr) = rr.get_addr(c_ares::DnsRrKey::A_ADDR) {
                            println!("{domain} has address {addr}");
                        }
                    }
                }
            }
            Err(e) => eprintln!("Query failed: {e}"),
        })?;

        // The event thread drives I/O in the background — in this example we just wait for all
        // pending queries to complete.
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
