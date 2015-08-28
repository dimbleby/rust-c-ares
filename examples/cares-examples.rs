#[cfg(unix)]
fn main() {
    mod unix;
    unix::cares_epoll::main();
    unix::cares_epoll_resolver::main();
    unix::cares_event_loop::main();
    unix::cares_event_loop_resolver::main();
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
