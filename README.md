# rust-c-ares #

A Rust wrapper for the [`c-ares`](http://c-ares.haxx.se/) library, for asynchronous DNS requests.

[![Build Status](https://travis-ci.org/dimbleby/rust-c-ares.svg?branch=master)](https://travis-ci.org/dimbleby/rust-c-ares)

## Documentation ##

- API documentation is [here](http://dimbleby.github.io/rust-c-ares).
- There are some example programs [here](https://github.com/dimbleby/rust-c-ares/tree/master/examples).

## Installation ##

To use `c-ares`, add this to your `Cargo.toml`:

```toml
[dependencies]
c-ares = "*"
```

And add this to your crate root:

```rust
extern crate c_ares;
```

## Platforms ##

Development has taken place on Linux.  The library uses the `std::os::unix::io::RawFd` type to represent file descriptors - so if Rust doesn't consider that you have a Unix system, then this crate won't work for you.

It's a long-term goal to support other platforms - but don't hold your breath.

## Contributing ##

Contributions are welcome.  Please send pull requests!
