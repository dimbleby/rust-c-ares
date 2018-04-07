## 4.1.2 (7 Apr 2018)

* Bump c-types dependency (fixes minimal-versions build on OSX)

## 4.1.1 (7 Apr 2018)

* Bump metadeps dependency (fixes minimal-versions build)

## 4.1.0 (16 Feb 2018)

* pull upstream c-ares - their release 1.14.0
* have a few more functions take `const` channel
  * `ares_save_options`, `ares_timeout`, `ares_get_servers`, `ares_get_servers_ports`
* start maintaining a CHANGELOG
