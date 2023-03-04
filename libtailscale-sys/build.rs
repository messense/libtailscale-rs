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
    let status = Command::new("go")
        .args(["build", "-buildmode=c-archive", "-o"])
        .arg(out_dir.join("libtailscale.a"))
        .current_dir("libtailscale")
        .status()
        .expect("go build command failed to start");
    assert!(status.success());

    println!("cargo:rustc-link-search=native={}", out_dir.display());
    println!("cargo:rustc-link-lib=static=tailscale");

    let target = env::var("TARGET").unwrap_or_else(|_| "".to_owned());
    if target.contains("apple-") {
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
        println!("cargo:rustc-link-lib=framework=Security");
    }
}
