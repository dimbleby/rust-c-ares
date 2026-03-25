# Updating c-ares Bindings

This skill covers updating the vendored c-ares submodule and regenerating FFI bindings when a new c-ares version is released upstream.

## Steps

### 1. Update the vendored submodule
```sh
cd c-ares-sys/c-ares
git fetch --tags
git checkout v1.XX.Y   # the new release tag
cd ../..
```

### 2. Regenerate bindings

Run from the `c-ares-sys/` directory:
```sh
cd c-ares-sys
./generate-ffi.sh
```

This script requires `bindgen` and `cmake` on `PATH`. It will:
- Run `cmake` in the vendored submodule to produce build headers.
- Run `bindgen` on `c-ares/include/ares.h` to produce `src/ffi.rs`.
- Apply `ffi.patch` (hand-maintained patch that adds `#[cfg]` gates on version-specific struct fields, platform-specific type definitions, and `Debug` impls for union-containing structs).
- Run `generate-constants.pl` to produce `src/constants.rs` from `#define` values in `ares.h`.
- Run `cargo fmt`.

### 3. Update `ffi.patch`

The patch frequently needs updating when bindgen output changes. The workflow is:
1. Before running `generate-ffi.sh`, save the current patch's intent by reviewing it.
2. Run the script. If the patch fails to apply, regenerate it:
   - Run the `bindgen` and `generate-constants.pl` steps from the script manually (without the `patch` step) to get a fresh `src/ffi.rs`.
   - Copy `src/ffi.rs` to `src/ffi.rs.orig`.
   - Apply the same categories of edits the old patch made (see below).
   - Generate the new patch: `diff -u src/ffi.rs.orig src/ffi.rs > ffi.patch`
   - Run `cargo fmt`.

The patch handles these categories of changes:
- **Platform types**: Replaces bindgen's generated type definitions with imports from `c_types` (e.g., `fd_set`, `hostent`, `sockaddr`), `libc` (`timeval`), and `jni_sys` (Android).
- **Socket type**: Adds `ares_socket_t` using `std::os::unix::io::RawFd` / `std::os::windows::io::RawSocket`.
- **Version-gated struct fields**: Adds `#[cfg(cares1_XX)]` on fields in `ares_options` that only exist in newer c-ares versions.
- **Debug impls**: Adds manual `Debug` for structs containing unions (`ares_addrttl`, `ares_addr6ttl`) since bindgen cannot derive `Debug` for them.
- **Android FFI**: Adds `#[cfg(target_os = "android")]` blocks for `ares_library_init_jvm`, `ares_library_init_android`, `ares_library_android_initialized`.
- **Module attributes**: Adds `#![allow(non_camel_case_types, non_snake_case)]` at the top.

### 4. Add version gates if needed

If the new release introduces APIs you want to wrap, add a version gate to the build script of each crate that uses it (`c-ares/build.rs` and/or `c-ares-resolver/build.rs`):
```rust
println!("cargo::rustc-check-cfg=cfg(cares1_XX)");
if version >= 0x1_XX_00 {
    println!("cargo:rustc-cfg=cares1_XX");
}
```
Then gate new code with `#[cfg(cares1_XX)]`.

### 5. Update metadata
- `c-ares-sys/Cargo.toml` — bump the crate version.
- `c-ares-sys/CHANGELOG.md` — add a release entry.
- If the `c-ares-sys` version bump is a breaking change, update the dependency version in `c-ares/Cargo.toml` and `c-ares-resolver/Cargo.toml`.

### 6. Build and test
```sh
cargo build --workspace --features vendored
cargo test --workspace --features vendored
cargo clippy --workspace --tests --examples --features vendored -- -D warnings
```

For minor point releases (e.g., 1.34.4 → 1.34.5), typically only the submodule pointer and `ffi.rs` change. For major releases that add new APIs, you may also need to add version gates and wrap new functionality in the `c-ares` crate.
