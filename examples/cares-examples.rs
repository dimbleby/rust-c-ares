#[cfg(unix)]
mod unix;

#[cfg(windows)]
mod windows;

extern crate c_ares;

#[cfg(windows)]
extern crate winapi;

#[cfg(windows)]
extern crate ws2_32;

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
fn epoll_examples() {
    unix::cares_epoll::main();
    unix::cares_epoll_resolver::main();
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn epoll_examples() {}

#[cfg(unix)]
fn main() {
    let (vstr, vint) = c_ares::version();
    println!("Version {:x} ({})", vint, vstr);

    unix::cares_event_loop::main();
    unix::cares_futures::main();
    epoll_examples();
}

#[cfg(windows)]
fn main() {
    let (vstr, vint) = c_ares::version();
    println!("Version {:x} ({})", vint, vstr);

    windows::cares_select::main();
}
