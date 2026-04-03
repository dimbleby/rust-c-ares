// This example demonstrates how to use the DnsRecord API to build and send
// structured DNS queries, and to inspect the parsed responses.
//
// It uses epoll() for the event loop, so it only runs on Linux/Android.

#[cfg(all(cares1_28, unix, any(target_os = "linux", target_os = "android")))]
extern crate nix;

#[cfg(all(cares1_28, unix, any(target_os = "linux", target_os = "android")))]
mod example {
    extern crate c_ares;
    use nix::sys::epoll::{Epoll, EpollCreateFlags, EpollEvent, EpollFlags};
    use std::collections::HashSet;
    use std::os::fd::BorrowedFd;

    fn print_dnsrec_result(result: &c_ares::Result<&c_ares::DnsRecord>) {
        match result {
            Err(e) => {
                println!("DNS query failed with error '{}'", e);
            }
            Ok(record) => {
                println!("Successful DNS query (id={})...", record.id());
                println!("  Opcode: {}", record.opcode());
                println!("  Rcode:  {}", record.rcode());
                println!("  Flags:  {:?}", record.flags());

                // Print the question section.
                for (i, (name, qtype, qclass)) in record.queries().enumerate() {
                    println!("  Question {}: {} {} {}", i, name, qtype, qclass);
                }

                // Print answer resource records.
                println!(
                    "  {} answer RR(s):",
                    record.rr_count(c_ares::DnsSection::Answer)
                );
                for (i, rr) in record.rrs(c_ares::DnsSection::Answer).enumerate() {
                    println!(
                        "    [{}] {} {} {} TTL={}",
                        i,
                        rr.name(),
                        rr.rr_type(),
                        rr.dns_class(),
                        rr.ttl()
                    );
                    // Print type-specific data using the generic key-value API.
                    match rr.rr_type() {
                        c_ares::DnsRecordType::A => {
                            if let Some(addr) = rr.get_addr(c_ares::DnsRrKey::A_ADDR) {
                                println!("       Address: {}", addr);
                            }
                        }
                        c_ares::DnsRecordType::AAAA => {
                            if let Some(addr) = rr.get_addr6(c_ares::DnsRrKey::AAAA_ADDR) {
                                println!("       Address: {}", addr);
                            }
                        }
                        c_ares::DnsRecordType::MX => {
                            let pref = rr.get_u16(c_ares::DnsRrKey::MX_PREFERENCE);
                            let exchange = rr.get_str(c_ares::DnsRrKey::MX_EXCHANGE);
                            println!(
                                "       Preference: {}, Exchange: {}",
                                pref,
                                exchange.unwrap_or("<none>")
                            );
                        }
                        c_ares::DnsRecordType::TXT => {
                            for (j, data) in rr.abins(c_ares::DnsRrKey::TXT_DATA).enumerate() {
                                let text = std::str::from_utf8(data).unwrap_or("<not utf-8>");
                                println!("       TXT[{}]: {}", j, text);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }

    pub fn main() {
        // Create the c_ares::Channel.
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

        // Use query_dnsrec to query for A records.
        ares_channel
            .query_dnsrec(
                "google.com",
                c_ares::DnsCls::IN,
                c_ares::DnsRecordType::A,
                move |result| {
                    println!();
                    println!("=== A record query via query_dnsrec ===");
                    print_dnsrec_result(&result);
                },
            )
            .expect("query_dnsrec failed");

        // Build a custom DNS query using DnsRecord and send it with send_dnsrec.
        let mut query = c_ares::DnsRecord::new(
            0,
            c_ares::DnsFlags::RD,
            c_ares::DnsOpcode::Query,
            c_ares::DnsRcode::NoError,
        )
        .expect("Failed to create DnsRecord");
        query
            .query_add("google.com", c_ares::DnsRecordType::MX, c_ares::DnsCls::IN)
            .expect("Failed to add query");

        ares_channel
            .send_dnsrec(&query, move |result| {
                println!();
                println!("=== MX record query via send_dnsrec ===");
                print_dnsrec_result(&result);
            })
            .expect("send_dnsrec failed");

        // Run the event loop using epoll.
        let flags = EpollCreateFlags::empty();
        let epoll = Epoll::new(flags).expect("Failed to create epoll");
        let mut tracked_fds = HashSet::<c_ares::Socket>::new();
        loop {
            let mut new_tracked_fds = HashSet::new();
            for (fd, readable, writable) in &ares_channel.sockets() {
                let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
                let mut interest = EpollFlags::empty();
                if readable {
                    interest |= EpollFlags::EPOLLIN;
                }
                if writable {
                    interest |= EpollFlags::EPOLLOUT;
                }
                let mut event = EpollEvent::new(interest, fd as u64);
                if tracked_fds.remove(&fd) {
                    epoll
                        .modify(borrowed_fd, &mut event)
                        .expect("epoll.modify() failed");
                } else {
                    epoll.add(borrowed_fd, event).expect("epoll.add() failed");
                };
                new_tracked_fds.insert(fd);
            }
            for fd in tracked_fds {
                let borrowed_fd = unsafe { BorrowedFd::borrow_raw(fd) };
                let _ = epoll.delete(borrowed_fd);
            }
            tracked_fds = new_tracked_fds;
            if tracked_fds.is_empty() {
                break;
            }

            let empty_event = EpollEvent::new(EpollFlags::empty(), 0);
            let mut events = [empty_event; 2];
            let results = epoll.wait(&mut events, 500u16).expect("epoll_wait failed");

            match results {
                0 => {
                    ares_channel.process_fd(None, None);
                }
                n => {
                    for event in &events[0..n] {
                        let active_fd = event.data() as c_ares::Socket;
                        let rfd = event
                            .events()
                            .contains(EpollFlags::EPOLLIN)
                            .then_some(active_fd);
                        let wfd = event
                            .events()
                            .contains(EpollFlags::EPOLLOUT)
                            .then_some(active_fd);
                        ares_channel.process_fd(rfd, wfd);
                    }
                }
            }
        }
    }
}

#[cfg(all(cares1_28, unix, any(target_os = "linux", target_os = "android")))]
pub fn main() {
    example::main();
}

#[cfg(not(all(cares1_28, unix, any(target_os = "linux", target_os = "android"))))]
pub fn main() {
    println!("this example is not supported on this platform");
}
