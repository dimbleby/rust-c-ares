// This example uses fds() to find out which file descriptors c-ares wants us to listen on, and
// uses select() to satisfy those requirements.
#[cfg(windows)]
extern crate winapi;

#[cfg(windows)]
mod example {
    extern crate c_ares;

    use std::mem;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::ptr;
    use winapi::um::winsock2::{
        fd_set, select, timeval, WSACleanup, WSAStartup, FD_SETSIZE, SOCKET_ERROR, WSADATA,
    };

    fn print_soa_result(result: &c_ares::Result<c_ares::SOAResult>) {
        match *result {
            Err(ref e) => {
                println!("SOA lookup failed with error '{}'", e);
            }
            Ok(ref soa_result) => {
                println!("Successful SOA lookup...");
                println!(
                    "Name server: {}",
                    soa_result.name_server().to_string_lossy()
                );
                println!("Hostmaster: {}", soa_result.hostmaster().to_string_lossy());
                println!("Serial: {}", soa_result.serial());
                println!("Retry: {}", soa_result.retry());
                println!("Expire: {}", soa_result.expire());
                println!("Min TTL: {}", soa_result.min_ttl());
            }
        }
    }

    fn print_name_info_result(result: &c_ares::Result<c_ares::NameInfoResult>) {
        match *result {
            Err(ref e) => {
                println!("Name info lookup failed with error '{}'", e);
            }
            Ok(ref name_info_result) => {
                println!("Successful name info lookup...");
                if let Some(node) = name_info_result.node() {
                    println!("Node: {}", node.to_string_lossy());
                }
                if let Some(service) = name_info_result.service() {
                    println!("Service: {}", service.to_string_lossy());
                }
            }
        }
    }

    pub fn main() {
        // Windows peculiarities.
        unsafe {
            let mut wsadata = mem::MaybeUninit::<WSADATA>::uninit();
            WSAStartup(0x101, wsadata.as_mut_ptr());
        }

        // Create the c_ares::Channel.
        let mut options = c_ares::Options::new();
        options
            .set_domains(&["example.com"])
            .set_flags(c_ares::Flags::STAYOPEN)
            .set_timeout(500)
            .set_tries(3);
        let mut ares_channel =
            c_ares::Channel::with_options(options).expect("Failed to create channel");
        ares_channel
            .set_servers(&["8.8.8.8"])
            .expect("Failed to set servers");

        // Set up some queries.
        ares_channel.query_soa("google.com", move |result| {
            println!();
            print_soa_result(&result);
        });

        let ipv4 = "216.58.210.14".parse::<Ipv4Addr>().unwrap();
        let sock = SocketAddr::V4(SocketAddrV4::new(ipv4, 80));
        ares_channel.get_name_info(
            &sock,
            c_ares::NIFlags::LOOKUPHOST | c_ares::NIFlags::LOOKUPSERVICE,
            move |result| {
                println!();
                print_name_info_result(&result);
            },
        );

        let ipv6 = "2a00:1450:4009:80a::200e".parse::<Ipv6Addr>().unwrap();
        let sock = SocketAddr::V6(SocketAddrV6::new(ipv6, 80, 0, 0));
        ares_channel.get_name_info(
            &sock,
            c_ares::NIFlags::LOOKUPHOST | c_ares::NIFlags::LOOKUPSERVICE,
            move |result| {
                println!();
                print_name_info_result(&result);
            },
        );

        // While c-ares wants us to listen for events, do so..
        loop {
            let mut read_fds = fd_set {
                fd_count: 0,
                fd_array: [c_ares::SOCKET_BAD; FD_SETSIZE],
            };
            let mut write_fds = fd_set {
                fd_count: 0,
                fd_array: [c_ares::SOCKET_BAD; FD_SETSIZE],
            };
            let count = ares_channel.fds(&mut read_fds, &mut write_fds);
            if count == 0 {
                break;
            }

            // Wait for something to happen.
            let timeout = timeval {
                tv_sec: 0,
                tv_usec: 500_000,
            };
            let results =
                unsafe { select(0, &mut read_fds, &mut write_fds, ptr::null_mut(), &timeout) };

            // Process whatever happened.
            match results {
                SOCKET_ERROR => panic!("Socket error"),
                _ => ares_channel.process(&mut read_fds, &mut write_fds),
            }
        }
        unsafe {
            WSACleanup();
        }
    }
}

#[cfg(windows)]
pub fn main() {
    example::main();
}

#[cfg(not(windows))]
pub fn main() {
    println!("this example is not supported on this platform");
}
