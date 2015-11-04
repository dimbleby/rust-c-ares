#[cfg(unix)]
mod unix;

#[cfg(any(target_os = "linux", target_os = "android"))]
fn epoll_examples() {
    unix::cares_epoll::main();
    unix::cares_epoll_resolver::main();
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
fn epoll_examples() { }

#[cfg(unix)]
fn main() {
    unix::cares_event_loop::main();
    unix::cares_event_loop_resolver::main();
    epoll_examples();
}

#[cfg(windows)]
extern crate winapi;

#[cfg(windows)]
extern crate ws2_32;

#[cfg(windows)]
fn main() {
    mod windows;
    windows::cares_select::main();
}
