# rust-c-ares #

A Rust wrapper for the [`c-ares`](http://c-ares.haxx.se/) library, for asynchronous DNS requests.

[![Build Status](https://travis-ci.org/dimbleby/rust-c-ares.svg?branch=master)](https://travis-ci.org/dimbleby/rust-c-ares)
[![Build status](https://ci.appveyor.com/api/projects/status/d5tce0p747b7iud8/branch/master?svg=true)](https://ci.appveyor.com/project/dimbleby/rust-c-ares/branch/master)
[![crates.io](http://meritbadge.herokuapp.com/c-ares)](https://crates.io/crates/c-ares)

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

## Contributing ##

Contributions are welcome.  Please send pull requests!
