// Compile the BPF crate at src/bpf and copy the resulting eBPF object to
// OUT_DIR so main.rs can `include_bytes_aligned!` it.
//
// aya-build (the canonical helper) requires the BPF crate to be discoverable
// via `cargo build --package <name>` from this crate's directory, which only
// works when the BPF crate is a workspace member. Ours is intentionally NOT a
// workspace member — different target (bpfel-unknown-none) and toolchain
// (nightly + build-std) make it ergonomic to keep it as its own workspace
// root. So we drive the nightly cargo via `--manifest-path` ourselves.
//
// The RUSTFLAGS set here match aya-build's: `bpf_target_arch` cfg drives
// arch-specific code in aya-ebpf; `-Clink-arg=--btf` makes bpf-linker emit
// BTF in the object, which Aya needs for CO-RE.

use anyhow::{Context, Result, anyhow};
use std::ffi::OsString;
use std::path::PathBuf;
use std::process::Command;

fn main() -> Result<()> {
    build_bpf_subcrate("src/bpf")
}

fn build_bpf_subcrate(rel_dir: &str) -> Result<()> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let bpf_dir = manifest_dir.join(rel_dir);
    let bpf_manifest = bpf_dir.join("Cargo.toml");
    if !bpf_manifest.exists() {
        return Err(anyhow!("bpf manifest missing: {}", bpf_manifest.display()));
    }
    println!("cargo:rerun-if-changed={}", bpf_dir.display());

    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH")?;
    let endian = std::env::var("CARGO_CFG_TARGET_ENDIAN")?;
    let target_triple = match endian.as_str() {
        "little" => "bpfel-unknown-none",
        "big" => "bpfeb-unknown-none",
        other => return Err(anyhow!("unsupported endian: {other}")),
    };

    let mut rustflags = OsString::new();
    for s in [
        "--cfg=bpf_target_arch=\"",
        target_arch.as_str(),
        "\"",
        "\x1f",
        "-Cdebuginfo=2",
        "\x1f",
        "-Clink-arg=--btf",
    ] {
        rustflags.push(s);
    }

    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").context("OUT_DIR not set")?);
    // Workaround for rust-lang/cargo#6412 (cargo flocks itself if the nested
    // build shares the parent's target dir).
    let target_dir = out_dir.join("bpf-target");

    let mut cmd = Command::new("rustup");
    cmd.args([
        "run",
        "nightly",
        "cargo",
        "build",
        "--manifest-path",
    ])
    .arg(&bpf_manifest)
    .args([
        "-Z",
        "build-std=core",
        "--target",
        target_triple,
        "--release",
        "--target-dir",
    ])
    .arg(&target_dir);
    cmd.env("CARGO_ENCODED_RUSTFLAGS", rustflags);
    // Strip wrappers that would re-route to the stable host toolchain.
    for key in ["RUSTC", "RUSTC_WORKSPACE_WRAPPER"] {
        cmd.env_remove(key);
    }

    let status = cmd.status().with_context(|| format!("spawning {cmd:?}"))?;
    if !status.success() {
        return Err(anyhow!("bpf build failed: {status}"));
    }

    // BPF crate's [[bin]] name matches the userspace package name. Copy the
    // object so main.rs can `include_bytes_aligned!(concat!(env!("OUT_DIR"), "/<pkg>"))`.
    let pkg_name = std::env::var("CARGO_PKG_NAME")?;
    let built = target_dir.join(target_triple).join("release").join(&pkg_name);
    let dst = out_dir.join(&pkg_name);
    std::fs::copy(&built, &dst)
        .with_context(|| format!("copy {} -> {}", built.display(), dst.display()))?;
    Ok(())
}
