#[cfg(unix)]
mod unix;

#[cfg(windows)]
mod windows;

#[cfg(all(unix, any(target_os = "linux", target_os = "android")))]
fn epoll_examples() {
    unix::cares_epoll::main();
    unix::cares_epoll_resolver::main();
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "android"))))]
fn epoll_examples() { }

#[cfg(unix)]
fn main() {
    unix::cares_event_loop::main();
    unix::cares_event_loop_resolver::main();
    epoll_examples();
}

#[cfg(windows)]
fn main() {
    windows::cares_select::main();
}
