# Changelog

## Unreleased

- CAA record value is bytes, not a string

## 9.2.1 (26 May 2024)

- Include the whole API in docs

## 9.2.0 (26 May 2024)

- add `get_servers()`

## 9.1.0 (24 May 2024)

- c-ares 1.29.0

## 9.0.0 (23 February 2024)

- cares 1.27.0
  - breaking only because of the introduction of `ENOSERVER` into the
    `Error` enum

## 8.2.0 (30 November 2023)

- c-ares 1.23.0

## 8.1.0 (14 November 2023)

- c-ares 1.22.0

## 8.0.0 (11 November 2023)

- Support versions of c-ares back to 1.13.0
  - Breaking if you are using features from a new c-ares but building in an
    environment where an old c-ares is available
  - Then this crate will by default attempt to use the old c-ares: you should
    either remove the old c-ares from your environment, or set the `vendored`
    feature flag.

## 7.8.0 (28 October 2023)

- c-types 3.0.0
- add features `vendored` and `maybe-vendored`
  - default is `maybe-vendored` which preserves existing behaviour: look for
    a suitable installed `c-ares` else build the vendored copy
  - `vendored` requires use of the vendored copy
  - omit both features to require use of an already-installed `c-ares`

## 7.7.0 (14 Oct 2023)

- c-ares 1.20.1

## 7.6.0 (28 Jan 2023)

- c-ares 1.19.0
- put a lock around `ares_library_init()` and `ares_library_cleanup()`
  - these are not thread-safe
  - they only do anything at all on android, so it's unlikely that this matters
    to anyone

## 7.5.2 (6 Nov 2021)

- bump minimum bitflags dependency

## 7.5.1 (6 Nov 2021)

- feature "build-cmake" to use the cmake-based build for c-ares

## 7.5.0 (26 Oct 2021)

- Update dependencies
  - in particular, c-ares 1.18.0
- Expose `set_sortlist()`

## 7.4.0 (23 Aug 2021)

- `cargo diet` to reduce crate size
- Update dependencies
- Add support for URI records

## 7.3.0 (29 Nov 2020)

- Update dependencies
- Add support for CAA records

## 7.2.0 (15 Aug 2020)

- Update dependencies
- Modernize error handling: `description()` is soft-deprecated.

## 7.1.0 (2 Nov 2018)

- Take upstream c-ares 1.15.0
  - In particular, introduces `Options::set_resolvconf_path()`

## 7.0.0 (1 Jul 2018)

- Have several functions take arguments by value, per clippy's
  `trivially_copy_pass_by_ref`
- Remove `addresses()` from `CNameResults` - CNAME queries don't return
  addresses

## 6.0.0 (28 May 2018)

- Return `&CStr` mostly, rather than `&str`. The unchecked conversion in
  previous releases was not safe, so we let users decide how to deal with that.

## 5.0.4 (7 Apr 2018)

- Bump more dependencies (fixes minimal-versions build on OSX)

## 5.0.3 (7 Apr 2018)

- Bump c-ares-sys dependency (really fixes minimal-versions build)

## 5.0.2 (7 Apr 2018)

- Bump metadeps dependency (fixes minimal-versions build)

## 5.0.1 (4 Jan 2018)

- spurious republish (failed attempt to fix c-ares-resolver build errors)

## 5.0.0 (4 Jan 2018)

- winapi 0.3.3
- fix docs link in Cargo.toml

## 4.0.3 (23 Dec 2017)

- pull upstream c-ares
  - in particular, fix crashes on Android
- start maintaining a CHANGELOG
