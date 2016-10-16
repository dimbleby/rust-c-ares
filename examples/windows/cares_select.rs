// This example uses fds() to find out which file descriptors c-ares
// wants us to listen on, and uses select() to satisfy those requirements.
extern crate c_ares;

use winapi::winsock2::{
    fd_set,
    FD_SETSIZE,
    SOCKET_ERROR,
    timeval,
    WSADATA,
};
use ws2_32::{
    select,
    WSACleanup,
    WSAStartup,
};
use std::error::Error;
use std::mem;
use std::net::{
    Ipv4Addr,
    Ipv6Addr,
    SocketAddr,
    SocketAddrV4,
    SocketAddrV6,
};
use std::ptr;

fn print_soa_result(result: Result<c_ares::SOAResult, c_ares::Error>) {
    match result {
        Err(e) => {
            println!("SOA lookup failed with error '{}'", e.description());
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

fn print_name_info_result(
    result: Result<c_ares::NameInfoResult, c_ares::Error>) {
    match result {
        Err(e) => {
            println!(
                "Name info lookup failed with error '{}'",
                e.description());
        }
        Ok(name_info_result) => {
            println!("Successful name info lookup...");
            println!("Node: {}", name_info_result.node().unwrap_or("<None>"));
            println!(
                "Service: {}",
                name_info_result.service().unwrap_or("<None>"));
        }
    }
}

pub fn main() {
    // Windows peculiarities.
    unsafe {
        let mut wsadata: WSADATA = mem::uninitialized();
        WSAStartup(0x101, &mut wsadata);
    }

    // Create the c_ares::Channel.
    let mut options = c_ares::Options::new();
    options
        .set_domains(&["example.com"])
        .set_flags(c_ares::flags::STAYOPEN)
        .set_timeout(500)
        .set_tries(3);
    let mut ares_channel = c_ares::Channel::new(options)
        .expect("Failed to create channel");
    ares_channel.set_servers(&["8.8.8.8"]).expect("Failed to set servers");

    // Set up some queries.
    ares_channel.query_soa("google.com", move |result| {
        println!("");
        print_soa_result(result);
    });

    let ipv4 = "216.58.210.14".parse::<Ipv4Addr>().unwrap();
    let sock = SocketAddr::V4(SocketAddrV4::new(ipv4, 80));
    ares_channel.get_name_info(
        &sock,
        c_ares::ni_flags::LOOKUPHOST | c_ares::ni_flags::LOOKUPSERVICE,
        move |result| {
            println!("");
            print_name_info_result(result);
        }
    );

    let ipv6 = "2a00:1450:4009:80a::200e".parse::<Ipv6Addr>().unwrap();
    let sock = SocketAddr::V6(SocketAddrV6::new(ipv6, 80, 0, 0));
    ares_channel.get_name_info(
        &sock,
        c_ares::ni_flags::LOOKUPHOST | c_ares::ni_flags::LOOKUPSERVICE,
        move |result| {
            println!("");
            print_name_info_result(result);
        }
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
        if count == 0 { break }

        // Wait for something to happen.
        let timeout = timeval {
            tv_sec: 0,
            tv_usec: 500000,
        };
        let results = unsafe {
            select(0, &mut read_fds, &mut write_fds, ptr::null_mut(), &timeout)
        };

        // Process whatever happened.
        match results {
            SOCKET_ERROR => panic!("Socket error"),
            _ => ares_channel.process(&mut read_fds, &mut write_fds),
        }
    }
    unsafe { WSACleanup(); }
}
