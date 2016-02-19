extern crate gcc;
extern crate pkg_config;

use std::env;
use std::fs;
use std::path::PathBuf;
use std::process::Command;

macro_rules! t {
    ($e:expr) => (match $e {
        Ok(t) => t,
        Err(e) => panic!("{} return the error {}", stringify!($e), e),
    })
}

fn main() {
    // Use the installed libcares if it is available.
    if pkg_config::Config::new()
        .atleast_version("1.11.0")
            .find("libcares")
            .is_ok() {
        return
    }

    // MSVC builds are different.
    let target = env::var("TARGET").unwrap();
    if target.contains("msvc") {
        build_msvc(&target);
        return
    }

    // Set up compiler options.
    let mut cflags = env::var("CFLAGS").unwrap_or(String::new());
    if target.contains("i686") {
        cflags.push_str(" -m32");
    } else if target.contains("x86_64") {
        cflags.push_str(" -m64");
    }
    if !target.contains("i686") {
        cflags.push_str(" -fPIC");
    }

    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let build = dst.join("build");
    let _ = fs::create_dir(&build);

    let mut config_opts = Vec::new();
    config_opts.push("--disable-tests".to_string());
    config_opts.push("--enable-static=yes".to_string());
    config_opts.push("--enable-shared=no".to_string());
    config_opts.push("--enable-optimize".to_string());
    config_opts.push(format!("--prefix={}", dst.display()));

    // Prepare.
    let src = env::current_dir().unwrap();
    run(Command::new("sh")
                .current_dir(&src.join("c-ares"))
                .arg("buildconf"));
    run(Command::new("sh")
                .env("CFLAGS", &cflags)
                .current_dir(&build)
                .arg("-c")
                .arg(&format!("{} {}", src.join("c-ares/configure").display(),
                              config_opts.join(" "))));

    // Compile.
    run(Command::new(make())
                .arg(&format!("-j{}", env::var("NUM_JOBS").unwrap()))
                .current_dir(&build));

    // Link to compiled library.
    println!("cargo:rustc-link-search={}/.libs", build.display());
    println!("cargo:rustc-link-lib=static=cares");
}

fn run(cmd: &mut Command) {
    println!("running: {:?}", cmd);
    assert!(t!(cmd.status()).success());
}

fn make() -> &'static str {
    if cfg!(target_os = "freebsd") {"gmake"} else {"make"}
}

fn build_msvc(target: &str) {
    // Prepare.
    let src = env::current_dir().unwrap();
    let c_ares_dir = &src.join("c-ares");
    run(Command::new("cmd")
                .current_dir(c_ares_dir)
                .arg("/c")
                .arg("buildconf.bat"));

    // Compile.
    let mut cmd = gcc::windows_registry::find(target, "nmake.exe").unwrap();
    cmd.current_dir(c_ares_dir);
    cmd.args(&["/f", "Makefile.msvc", "CFG=lib-release", "c-ares"]);
    run(&mut cmd);

    // Install library.
    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let build = dst.join("build");
    let mut cmd = gcc::windows_registry::find(target, "nmake.exe").unwrap();
    cmd.current_dir(c_ares_dir);
    cmd.args(&["/f", "Makefile.msvc", "/a", "CFG=lib-release", "install"]);
    cmd.env("INSTALL_DIR", format!("{}", build.display()));
    run(&mut cmd);

    // Link to compiled library.
    println!("cargo:rustc-link-search={}/lib", build.display());
    println!("cargo:rustc-link-lib=static=libcares");
}
