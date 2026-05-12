// Build the BPF sub-crate at src/bpf and expose its object to main.rs via
// OUT_DIR. The sub-crate has its own toolchain (nightly + rust-src) and target
// (bpfel-unknown-none); aya-build orchestrates that. See SPECS.md §3.
//
// Skeleton commit: keep this stub until the rust toolchain is installed and
// the exact aya-build 0.1.3 entry-point is verified against a clean build —
// CLAUDE.md forbids guessing at API. The real call goes here.

fn main() {
    println!("cargo:rerun-if-changed=src/bpf");
}
