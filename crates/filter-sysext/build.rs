//! Compiles the unified-logging C shim. See `oslog_shim.c` for why it exists.

fn main() {
    println!("cargo:rerun-if-changed=oslog_shim.c");
    cc::Build::new()
        .file("oslog_shim.c")
        .compile("digiexam_oslog_shim");
}
