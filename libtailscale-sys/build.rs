use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=libtailscale/tailscale.h");
    println!("cargo:rerun-if-changed=libtailscale/tailscale.c");
    println!("cargo:rerun-if-changed=libtailscale/tailscale.go");
    println!("cargo:rerun-if-changed=libtailscale/go.mod");
    println!("cargo:rerun-if-changed=libtailscale/go.sum");

    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let host = env::var("HOST").unwrap();
    let target = env::var("TARGET").unwrap();

    let mut cmd = Command::new("go");
    if host != target {
        let os = if target.contains("android") {
            "android"
        } else if target.contains("darwin") {
            "darwin"
        } else if target.contains("dragonfly") {
            "dragonfly"
        } else if target.contains("freebsd") {
            "freebsd"
        } else if target.contains("dragonfly") {
            "dragonfly"
        } else if target.contains("illumos") {
            "illumos"
        } else if target.contains("ios") {
            "ios"
        } else if target.contains("linux") {
            "linux"
        } else if target.contains("netbsd") {
            "netbsd"
        } else if target.contains("openbsd") {
            "openbsd"
        } else if target.contains("solaris") {
            "solaris"
        } else if target.contains("windows") {
            "windows"
        } else {
            panic!("unsupported operating system")
        };
        let arch = if target.contains("i386") || target.contains("i585") || target.contains("i686")
        {
            "386"
        } else if target.contains("x86_64") {
            "amd64"
        } else if target.contains("aarch64") {
            "arm64"
        } else if target.contains("armeb") {
            "armbe"
        } else if target.contains("arm") {
            "arm"
        } else if target.contains("mips64el-") {
            "mips64le"
        } else if target.contains("mips64-") {
            "mips64"
        } else if target.contains("mipsel") {
            "mipsle"
        } else if target.contains("mips-") {
            "mips"
        } else if target.contains("powerpc64le-") {
            "ppc64le"
        } else if target.contains("powerpc64-") {
            "ppc64"
        } else if target.contains("powerpc-") {
            "ppc"
        } else if target.contains("riscv64") {
            "riscv64"
        } else if target.contains("riscv32") {
            "riscv"
        } else if target.contains("s390x") {
            "s390x"
        } else if target.contains("sparc64") {
            "sparc64"
        } else if target.contains("sparc-") {
            "sparc"
        } else if target.contains("wasm") {
            "wasm"
        } else {
            panic!("unsupported cpu architecture")
        };
        cmd.env("CGO_ENABLED", "1")
            .env("GOOS", os)
            .env("GOARCH", arch);
    }

    let status = cmd
        .args(["build", "-buildmode=c-archive", "-o"])
        .arg(out_dir.join("libtailscale.a"))
        .current_dir("libtailscale")
        .status()
        .expect("go build command failed to start");
    assert!(status.success());

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=tailscale");

    if target.contains("apple-") {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
    }
}
