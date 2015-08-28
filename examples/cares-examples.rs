#[cfg(unix)]
fn main() {
    mod unix;
    unix::cares_event_loop::main();
    unix::cares_event_loop_resolver::main();
    unix::cares_poll::main();
    unix::cares_poll_resolver::main();
}

#[cfg(windows)]
fn main() {
    mod windows;
    windows::cares_select::main();
}
