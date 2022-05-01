# rust-c-ares

A Rust wrapper for the [`c-ares`](https://c-ares.org/) library, for
asynchronous DNS requests.

Most users should likely prefer
[`c-ares-resolver`](https://github.com/dimbleby/c-ares-resolver/), which offers
a much simpler API.

[![Crates.io][crates-badge]][crates-url]
[![Build Status][actions-badge]][actions-url]

[crates-badge]: https://img.shields.io/crates/v/c-ares.svg
[crates-url]: https://crates.io/crates/c-ares
[actions-badge]: https://github.com/dimbleby/rust-c-ares/actions/workflows/build.yml/badge.svg
[actions-url]: https://github.com/dimbleby/rust-c-ares/actions?query=workflow%3ACI+branch%3Amain

## Documentation

- API documentation is [here](https://docs.rs/c-ares).
- There are some example programs
  [here](https://github.com/dimbleby/rust-c-ares/tree/main/examples).

Setting the feature `build-cmake` will cause the `c-ares` library to be built
using `cmake`.
This is significantly faster than the default `autotools` build on unix
platforms: so if it works for you, you should probably prefer it.

## Contributing

Contributions are welcome. Please send pull requests!
