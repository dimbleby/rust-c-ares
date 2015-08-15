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
    match pkg_config::Config::new().atleast_version("1.10.0").find("libcares") {
        Ok(..) => return,
        Err(..) => {}
    }

    // Compile the bundled libcares.
    let target = env::var("TARGET").unwrap();
    let src = env::current_dir().unwrap();
    let dst = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let build = dst.join("build");

    println!("cargo:rustc-link-search={}/.libs", build.display());
    println!("cargo:rustc-link-lib=static=cares");

    let mut cflags = env::var("CFLAGS").unwrap_or(String::new());
    if target.contains("i686") {
        cflags.push_str(" -m32");
    } else if target.contains("x86_64") {
        cflags.push_str(" -m64");
    }
    if !target.contains("i686") {
        cflags.push_str(" -fPIC");
    }

    let _ = fs::create_dir(&build);

    let mut config_opts = Vec::new();
    config_opts.push("--enable-static=yes".to_string());
    config_opts.push("--enable-shared=no".to_string());
    config_opts.push("--enable-optimize".to_string());
    config_opts.push(format!("--prefix={}", dst.display()));

    run(Command::new("sh")
                .current_dir(&src.join("c-ares"))
                .arg("buildconf"));
    run(Command::new("sh")
                .env("CFLAGS", &cflags)
                .current_dir(&build)
                .arg("-c")
                .arg(&format!("{} {}", src.join("c-ares/configure").display(),
                              config_opts.connect(" "))));
    run(Command::new(make())
                .arg(&format!("-j{}", env::var("NUM_JOBS").unwrap()))
                .current_dir(&build));
}

fn run(cmd: &mut Command) {
    println!("running: {:?}", cmd);
    assert!(t!(cmd.status()).success());
}

fn make() -> &'static str {
    if cfg!(target_os = "freebsd") {"gmake"} else {"make"}
}
