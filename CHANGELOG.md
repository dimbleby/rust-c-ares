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
