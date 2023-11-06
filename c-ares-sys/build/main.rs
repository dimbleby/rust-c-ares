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
    if let Ok(p) = system_deps::Config::new().probe() {
        return p
            .all_include_paths()
            .into_iter()
            .map(|x| x.to_owned())
            .collect();
    }

    #[cfg(not(feature = "maybe-vendored"))]
    panic!(
        "no pre installed c-ares library found, \
         you may want to install it or use the maybe-vendored feature"
    );

    #[cfg(feature = "maybe-vendored")]
    vendored::build()
}

fn check_version(include_dirs: &[PathBuf]) {
    println!("cargo:rerun-if-changed=build/expando.c");
    let mut gcc = cc::Build::new();
    gcc.includes(include_dirs);
    let expanded = match gcc.file("build/expando.c").try_expand() {
        Ok(expanded) => expanded,
        Err(e) => panic!("Failed to get c-ares headers: {e}"),
    };
    let expanded = String::from_utf8(expanded).unwrap();

    let mut c_ares_version = None;
    for line in expanded.lines() {
        let line = line.trim();

        if let Some(version) = line.strip_prefix("RUST_VERSION_C_ARES_") {
            c_ares_version = Some(parse_version(version));
        }
    }

    let version = c_ares_version.unwrap();
    println!("cargo:version_number={version:x}");

    if version >= 0x1_0f_00 {
        // 1.15.0
        println!("cargo:rustc-cfg=cares1_15");
    }

    if version >= 0x1_11_00 {
        // 1.17.0
        println!("cargo:rustc-cfg=cares1_17");
    }

    if version >= 0x1_12_00 {
        // 1.18.0
        println!("cargo:rustc-cfg=cares1_18");
    }

    if version >= 0x1_13_00 {
        // 1.19.0
        println!("cargo:rustc-cfg=cares1_19");
    }

    if version >= 0x1_14_00 {
        // 1.20.0
        println!("cargo:rustc-cfg=cares1_20");
    }
}

fn parse_version(version: &str) -> u64 {
    println!("version: {version}");
    let mut it = version.split('_');
    let major = it.next().unwrap().parse::<u64>().unwrap();
    let minor = it.next().unwrap().parse::<u64>().unwrap();
    let patch = it.next().unwrap().parse::<u64>().unwrap();

    (major << 16) | (minor << 8) | patch
}
