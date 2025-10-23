use std::path::PathBuf;

#[cfg(feature = "maybe-vendored")]
mod vendored;

fn main() {
    let include_dirs = get_cares();
    check_version(&include_dirs);
}

fn get_cares() -> Vec<PathBuf> {
    // Use the installed libcares if it is available.
    #[cfg(not(feature = "vendored"))]
    if let Some(p) = probe_installed() {
        return p;
    }

    #[cfg(not(feature = "maybe-vendored"))]
    panic!(
        "no pre installed c-ares library found, \
         you may want to install it or use the maybe-vendored feature"
    );

    #[cfg(feature = "maybe-vendored")]
    vendored::build()
}

fn probe_installed() -> Option<Vec<PathBuf>> {
    if let Ok(lib) = pkg_config::Config::new()
        .atleast_version("1.13.0")
        .print_system_libs(false)
        .probe("libcares")
    {
        return Some(lib.include_paths);
    }

    if let Ok(lib) = vcpkg::Config::new()
        .emit_includes(true)
        .find_package("c-ares")
    {
        return Some(lib.include_paths);
    }

    None
}

fn check_version(include_dirs: &[PathBuf]) {
    println!("cargo:rerun-if-changed=build/expando.c");
    let expanded = cc::Build::new()
        .includes(include_dirs)
        .file("build/expando.c")
        .expand();
    let expanded = String::from_utf8(expanded).unwrap();

    let version = expanded
        .lines()
        .find_map(|line| line.trim().strip_prefix("RUST_VERSION_C_ARES_"))
        .map(parse_version)
        .unwrap();

    println!("cargo:version_number={version:x}");

    println!("cargo::rustc-check-cfg=cfg(cares1_15)");
    if version >= 0x1_0f_00 {
        println!("cargo:rustc-cfg=cares1_15");
    }

    println!("cargo::rustc-check-cfg=cfg(cares1_18)");
    if version >= 0x1_12_00 {
        println!("cargo:rustc-cfg=cares1_18");
    }

    println!("cargo::rustc-check-cfg=cfg(cares1_19)");
    if version >= 0x1_13_00 {
        println!("cargo:rustc-cfg=cares1_19");
    }

    println!("cargo::rustc-check-cfg=cfg(cares1_20)");
    if version >= 0x1_14_00 {
        println!("cargo:rustc-cfg=cares1_20");
    }

    println!("cargo::rustc-check-cfg=cfg(cares1_22)");
    if version >= 0x1_16_00 {
        println!("cargo:rustc-cfg=cares1_22");
    }

    println!("cargo::rustc-check-cfg=cfg(cares1_23)");
    if version >= 0x1_17_00 {
        println!("cargo:rustc-cfg=cares1_23");
    }

    println!("cargo::rustc-check-cfg=cfg(cares1_26)");
    if version >= 0x1_1a_00 {
        println!("cargo:rustc-cfg=cares1_26");
    }

    println!("cargo::rustc-check-cfg=cfg(cares1_29)");
    if version >= 0x1_1d_00 {
        println!("cargo:rustc-cfg=cares1_29");
    }
}

fn parse_version(version: &str) -> u64 {
    let mut it = version.split('_');
    let major: u64 = it.next().unwrap().parse().unwrap();
    let minor: u64 = it.next().unwrap().parse().unwrap();
    let patch: u64 = it.next().unwrap().parse().unwrap();

    (major << 16) | (minor << 8) | patch
}
