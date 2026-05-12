// See crates/tragach-slowquery/build.rs for the rationale. Same stub —
// real aya-build invocation lands once the toolchain is verified.

fn main() {
    println!("cargo:rerun-if-changed=src/bpf");
}
