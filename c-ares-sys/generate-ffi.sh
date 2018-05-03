#!/bin/bash
set -e

if ! command -v bindgen > /dev/null 2>&1
then
  echo "bindgen is not in the path"
  exit 1
fi

# Prepare for bindgen, and do it.
(cd c-ares && ./buildconf && ./configure)
bindgen --blacklist-type="__.*" \
        --blacklist-type="ares_socket_t" \
        --blacklist-type="fd_set" \
        --blacklist-type="hostent" \
        --blacklist-type="iovec" \
        --blacklist-type="sockaddr" \
        --blacklist-type="sa_family_t" \
        --blacklist-type="socklen_t" \
        --blacklist-type="timeval" \
        --whitelist-function="ares.*" \
        --whitelist-type="ares.*" \
        --whitelist-type="apattern" \
        --no-layout-tests \
        --output=src/ffi.rs \
        c-ares/ares.h

# Apply manual patches.
patch -p0 < ffi.patch

# Generate constants.
./generate-constants.pl > src/constants.rs
