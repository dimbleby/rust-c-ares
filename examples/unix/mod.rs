pub mod cares_event_loop;
pub mod cares_event_loop_resolver;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod cares_epoll;

#[cfg(any(target_os = "linux", target_os = "android"))]
pub mod cares_epoll_resolver;
