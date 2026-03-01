# c-ares-resolver

DNS resolvers built on [`c-ares`](https://crates.io/crates/c-ares), for
asynchronous DNS requests.

This crate provides three resolver types - the `Resolver`, the `FutureResolver`,
and the `BlockingResolver`:

- The `Resolver` is the thinnest wrapper around the underlying `c-ares` library.
  It returns answers via callbacks.
  The other resolvers are built on top of this.
- The `FutureResolver` returns answers as `std::future::Future`s.
- The `BlockingResolver` isn't asynchronous at all - as the name suggests, it
  blocks until the lookup completes.

[![Crates.io][crates-badge]][crates-url]

[crates-badge]: https://img.shields.io/crates/v/c-ares-resolver.svg
[crates-url]: https://crates.io/crates/c-ares-resolver

## Documentation

API documentation is [here](https://docs.rs/c-ares-resolver).

## Examples

```rust
use futures_executor::block_on;

fn main() {
    let resolver = c_ares_resolver::FutureResolver::new().unwrap();
    let query = resolver.query_a("google.com");
    let response = block_on(query);
    match response {
        Ok(result) => println!("{}", result),
        Err(e) => println!("Lookup failed with error '{}'", e)
    }
}
```

Further example programs can be found
[here](https://github.com/dimbleby/rust-c-ares/tree/main/c-ares-reolver/examples).
