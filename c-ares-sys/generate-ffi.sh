#!/bin/bash
set -e

if ! command -v bindgen > /dev/null 2>&1
then
  echo "bindgen is not in the path"
  exit 1
fi

# Prepare for bindgen, and do it.
mkdir -p c-ares/build
(cd c-ares/build && cmake ..)
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
        --opaque-type="in_addr_t" \
        --size_t-is-usize \
        --no-layout-tests \
        --output=src/ffi.rs \
        c-ares/include/ares.h \
        -- \
        -Ic-ares/build
rm -fr c-ares/build

# Apply manual patches.
patch -p0 < ffi.patch

# Generate constants.
./generate-constants.pl > src/constants.rs
