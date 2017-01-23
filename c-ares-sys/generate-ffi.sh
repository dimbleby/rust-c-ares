#!/bin/bash

if ! which bindgen > /dev/null 2>&1
then
  echo "bindgen is not in the path"
  exit 1
fi

# Prepare for bindgen, do it, and then apply manual patches.
(cd c-ares && ./buildconf && ./configure)
bindgen --whitelist-function="ares.*" --whitelist-type="ares.*" --blacklist-type="fd_set" --blacklist-type="hostent" --blacklist-type="in_addr" --blacklist-type="sockaddr" --blacklist-type="socklen_t" --blacklist-type="timeval" --no-unstable-rust --output=src/ffi.rs c-ares/ares.h
patch -p0 < ffi.patch

# Generate constants.
./generate-constants.pl > src/constants.rs
