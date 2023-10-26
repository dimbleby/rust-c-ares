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
bindgen --allowlist-function="ares.*" \
        --allowlist-type="apattern" \
        --allowlist-type="ares.*" \
        --blocklist-type="__.*" \
        --blocklist-type="ares_socket_t" \
        --blocklist-type="fd_set" \
        --blocklist-type="hostent" \
        --blocklist-type="iovec" \
        --blocklist-type="sa_family_t" \
        --blocklist-type="sockaddr" \
        --blocklist-type="socklen_t" \
        --blocklist-type="timeval" \
        --default-enum-style="rust" \
        --opaque-type="in_addr_t" \
        --no-debug="ares_addrttl" \
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
