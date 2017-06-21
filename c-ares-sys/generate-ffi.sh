#!/bin/bash

if ! which bindgen > /dev/null 2>&1
then
  echo "bindgen is not in the path"
  exit 1
fi

# Prepare for bindgen, and do it.
(cd c-ares && ./buildconf && ./configure)
bindgen --blacklist-type="ares_socket_t" \
        --whitelist-function="ares.*" \
        --whitelist-type="ares.*" \
        --whitelist-type="apattern" \
        --no-recursive-whitelist \
        --no-layout-tests \
        --output=src/ffi.rs \
        c-ares/ares.h

# Apply manual patches.
patch -p0 < ffi.patch

# Generate constants.
./generate-constants.pl > src/constants.rs
