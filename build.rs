// rtp-rs is a pure-Rust binary codec with no native or Swift dependencies.
// The build script exists only to keep the crate layout consistent with the
// rest of the workspace and to give a single place to hang future codegen.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
}
