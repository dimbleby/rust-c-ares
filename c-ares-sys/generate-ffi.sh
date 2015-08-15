#!/bin/bash

if ! which bindgen > /dev/null 2>&1
then
  echo "bindgen is not in the path"
  exit 1
fi

(cd c-ares && ./buildconf && ./configure)
~/rust-bindgen/target/release/bindgen -l cares -match ares -o src/ffi.rs c-ares/ares.h
patch -p0 < ffi.patch
