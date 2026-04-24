//! Build script: compile `shannon-ebpf` as a BPF ELF and put the resulting
//! object bytes inside `$OUT_DIR/shannon-ebpf` so userspace can load it with
//! `include_bytes_aligned!`.
//!
//! We intentionally don't depend on `aya-build` — that crate wires itself
//! into Cargo too aggressively and plays poorly with our dual-workspace
//! layout. Instead we shell out to nightly cargo from here, which matches
//! exactly what `cargo xtask build` does.

use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("cargo sets OUT_DIR"));
    let manifest_dir =
        PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("cargo sets MANIFEST_DIR"));
    let ebpf_dir = manifest_dir
        .parent()
        .expect("workspace root")
        .join("shannon-ebpf");

    println!("cargo:rerun-if-changed={}", ebpf_dir.join("src").display());
    println!(
        "cargo:rerun-if-changed={}",
        ebpf_dir.join("Cargo.toml").display()
    );

    let profile = std::env::var("PROFILE").unwrap_or_else(|_| "debug".into());

    // cargo invokes build.rs with CARGO pointing at the stable proxy for the
    // outer build. Stable cargo doesn't honour `+nightly`, so we go through
    // the rustup proxy explicitly. Clearing CARGO and any inherited
    // toolchain / target env is belt-and-braces.
    let mut cmd = Command::new("rustup");
    cmd.current_dir(&ebpf_dir).args([
        "run",
        "nightly",
        "cargo",
        "build",
        "-Z",
        "build-std=core",
        "--target",
        "bpfel-unknown-none",
    ]);
    if profile == "release" {
        cmd.arg("--release");
    }
    cmd.env_remove("CARGO");
    cmd.env_remove("CARGO_BUILD_TARGET");
    cmd.env_remove("CARGO_TARGET_DIR");
    cmd.env_remove("CARGO_ENCODED_RUSTFLAGS");
    cmd.env_remove("RUSTFLAGS");
    cmd.env_remove("RUSTC");
    cmd.env_remove("RUSTUP_TOOLCHAIN");
    // Clippy injects these to wrap rustc with clippy-driver. Without
    // stripping them here, the inner nightly `cargo build -Z build-std=core`
    // ends up linting libcore with the *outer* toolchain's clippy-driver,
    // which fails on intrinsics newer than that driver knows about.
    cmd.env_remove("RUSTC_WRAPPER");
    cmd.env_remove("RUSTC_WORKSPACE_WRAPPER");

    let status = cmd
        .status()
        .expect("failed to spawn rustup/cargo for shannon-ebpf");
    assert!(status.success(), "shannon-ebpf build failed");

    let src = ebpf_dir
        .join("target")
        .join("bpfel-unknown-none")
        .join(&profile)
        .join("shannon-ebpf");
    let dst = out_dir.join("shannon-ebpf");
    std::fs::copy(&src, &dst).unwrap_or_else(|e| {
        panic!(
            "copying BPF object {} -> {}: {e}",
            src.display(),
            dst.display()
        )
    });

    // Expose the path at compile time for the Rust `include_bytes!` macro.
    println!("cargo:rustc-env=SHANNON_EBPF_OBJ={}", dst.display());

    // Optional: stamp the git sha into the binary if we're in a checkout.
    if let Ok(out) = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
    {
        if out.status.success() {
            if let Ok(sha) = String::from_utf8(out.stdout) {
                println!("cargo:rustc-env=SHANNON_GIT_SHA={}", sha.trim());
            }
        }
    }
}
