## 5.1.0 (29 Nov 2020)

- Take c-ares 1.17.1

## 5.0.0 (15 Aug 2020)

- pull upstream c-ares - their release 1.16.1
- switch to using `RawSocket` on windows

## 4.2.0 (2 Nov 2018)

- pull upstream c-ares - their release 1.15.0

## 4.1.5 (1 Jul 2018)

- pull upstream c-ares

## 4.1.4 (30 May 2018)

- pull upstream c-ares
  - in particular, their [#191](https://github.com/c-ares/c-ares/pull/191)

## 4.1.3 (12 May 2018)

- Arrange that build output all goes to `$OUT_DIR`

## 4.1.2 (7 Apr 2018)

- Bump c-types dependency (fixes minimal-versions build on OSX)

## 4.1.1 (7 Apr 2018)

- Bump metadeps dependency (fixes minimal-versions build)

## 4.1.0 (16 Feb 2018)

- pull upstream c-ares - their release 1.14.0
- have a few more functions take `const` channel
  - `ares_save_options`, `ares_timeout`, `ares_get_servers`,
    `ares_get_servers_ports`
- start maintaining a CHANGELOG
