extern crate cc;
extern crate fs_extra;
extern crate metadeps;

use std::env;
#[cfg(not(feature = "build-cmake"))]
use std::ffi::OsString;
use std::fs;
use std::path::PathBuf;
#[cfg(not(feature = "build-cmake"))]
use std::process::Command;

fn main() {
    // Rerun if the c-ares source code has changed.
    println!("cargo:rerun-if-changed=c-ares");

    // Use the installed libcares if it is available.
    if metadeps::probe().is_ok() {
        return;
    }

    // We'll compile from source.  Clean up previous build, if any.
    let outdir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let build = outdir.join("build");
    let _ = fs::remove_dir_all(&build);
    fs::create_dir(&build).unwrap();

    // Copy the c-ares source code into $OUT_DIR, where it's safe for the build
    // process to modify it.
    let c_ares_dir = outdir.join("c-ares");
    let _ = fs::remove_dir_all(&c_ares_dir);
    let copy_options = fs_extra::dir::CopyOptions::new();
    let src = env::current_dir().unwrap().join("c-ares");
    fs_extra::dir::copy(src, &outdir, &copy_options).unwrap();

    // Export the include path for crates dependending on c-ares
    println!("cargo:include={}", c_ares_dir.join("include").display());

    compile();
}

#[cfg(feature = "build-cmake")]
fn compile() {
    let outdir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let c_ares_dir = outdir.join("c-ares");
    let dst = cmake::Config::new(c_ares_dir)
        .define("CARES_STATIC", "ON")
        .define("CARES_SHARED", "OFF")
        .define("CARES_BUILD_TOOLS", "OFF")
        .define("CMAKE_INSTALL_LIBDIR", "lib")
        .build();

    println!("cargo:rustc-link-search={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=cares");
}

#[cfg(not(feature = "build-cmake"))]
fn run(cmd: &mut Command) {
    println!("running: {:?}", cmd);
    match cmd.status() {
        Ok(t) => assert!(t.success()),
        Err(e) => panic!("{} return the error {}", stringify!($e), e),
    }
}

#[cfg(not(feature = "build-cmake"))]
const fn make() -> &'static str {
    if cfg!(target_os = "freebsd") {
        "gmake"
    } else {
        "make"
    }
}

#[cfg(not(feature = "build-cmake"))]
fn nmake(target: &str) -> Command {
    // cargo messes with the environment in a way that nmake does not like -
    // see https://github.com/rust-lang/cargo/issues/4156.  Explicitly remove
    // the unwanted variables.
    let mut cmd = cc::windows_registry::find(target, "nmake.exe").unwrap();
    cmd.env_remove("MAKEFLAGS").env_remove("MFLAGS");
    cmd
}

#[cfg(not(feature = "build-cmake"))]
fn compile() {
    // MSVC builds are different.
    let target = env::var("TARGET").unwrap();
    if target.contains("msvc") {
        build_msvc(&target);
        return;
    }

    // Prepare.
    let outdir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let c_ares_dir = outdir.join("c-ares");
    let build = outdir.join("build");
    run(Command::new("sh").current_dir(&c_ares_dir).arg("buildconf"));

    // Configure.
    let cfg = cc::Build::new();
    let compiler = cfg.get_compiler();
    let mut cflags = OsString::new();
    for arg in compiler.args() {
        cflags.push(arg);
        cflags.push(" ");
    }

    let mut cmd = Command::new("sh");
    cmd.env("CFLAGS", &cflags)
        .env("CC", compiler.path())
        .current_dir(&build)
        .arg(format!("{}", c_ares_dir.join("configure").display()))
        .arg("--enable-static")
        .arg("--disable-shared")
        .arg("--enable-optimize")
        .arg("--disable-debug")
        .arg("--disable-tests")
        .arg(format!("--prefix={}", outdir.display()));

    // This code fragment copied from curl-rust... c-ares and curl come from
    // the same developer so are usually pretty similar, and this seems to
    // work.
    //
    // NOTE GNU terminology
    // BUILD = machine where we are (cross) compiling
    // HOST = machine where the compiled binary will be used
    // TARGET = only relevant when compiling compilers
    let host = env::var("HOST").unwrap();
    if target != host && (!target.contains("windows") || !host.contains("windows")) {
        if target.contains("windows") {
            cmd.arg(format!("--host={}", host));
            cmd.arg(format!("--target={}", target));
        } else {
            cmd.arg(format!("--build={}", host));
            cmd.arg(format!("--host={}", target));
        }
    }
    run(&mut cmd);

    // Compile.
    run(Command::new(make())
        .arg(format!("-j{}", env::var("NUM_JOBS").unwrap()))
        .current_dir(&build));

    // Link to compiled library.
    println!("cargo:rustc-link-search={}/src/lib/.libs", build.display());
    if cfg!(target_os = "macos") {
        println!("cargo:rustc-link-lib=static=resolv");
    }
    println!("cargo:rustc-link-lib=static=cares");
}

#[cfg(not(feature = "build-cmake"))]
fn build_msvc(target: &str) {
    // Prepare.  We've already copied the c-ares source code into the output
    // directory.
    let outdir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let c_ares_dir = outdir.join("c-ares");
    run(Command::new("cmd")
        .current_dir(&c_ares_dir)
        .arg("/c")
        .arg("buildconf.bat"));

    // Compile.
    let mut cmd = nmake(target);
    cmd.current_dir(&c_ares_dir);
    cmd.args(["/f", "Makefile.msvc", "CFG=lib-release", "c-ares"]);
    run(&mut cmd);

    // Install library.
    let build = outdir.join("build");
    let mut cmd = nmake(target);
    cmd.current_dir(&c_ares_dir);
    cmd.args(["/f", "Makefile.msvc", "/a", "CFG=lib-release", "install"]);
    cmd.env("INSTALL_DIR", format!("{}", build.display()));
    run(&mut cmd);

    // Link to compiled library.
    println!("cargo:rustc-link-search={}/lib", build.display());
    println!("cargo:rustc-link-lib=iphlpapi");
    println!("cargo:rustc-link-lib=static=libcares");
}
