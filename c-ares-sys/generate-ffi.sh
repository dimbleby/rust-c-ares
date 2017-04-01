#!/bin/bash

if ! which bindgen > /dev/null 2>&1
then
  echo "bindgen is not in the path"
  exit 1
fi

# Prepare for bindgen, do it, and then apply manual patches.
(cd c-ares && ./buildconf && ./configure)
bindgen --whitelist-function="ares.*" --whitelist-type="ares.*" --whitelist-type="apattern" --no-recursive-whitelist --no-unstable-rust --output=src/ffi.rs c-ares/ares.h
patch -p0 < ffi.patch

# bindgen converts 'char' to 'c_schar' - see https://github.com/servo/rust-bindgen/issues/603.
# Since c-ares never uses 'signed char' we can compensate with simple search-and-replace.
sed -i 's/c_schar/c_char/g' src/ffi.rs

# Generate constants.
./generate-constants.pl > src/constants.rs
