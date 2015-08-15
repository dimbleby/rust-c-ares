#!/bin/bash

if ! which bindgen > /dev/null 2>&1
then
  echo "bindgen is not in the path"
  exit 1
fi

# Prepare for bindgen, do it, and then apply manual patches.
(cd c-ares && ./buildconf && ./configure)
bindgen -l cares -match ares -o src/ffi.rs c-ares/ares.h
patch -p0 < ffi.patch

# Generate constants.
./generate-constants.pl > src/constants.rs
