//! Build script for the `engine-ffi` crate.
//!
//! ## Prerequisites
//!
//! Before compiling or testing this crate using Cargo (`cargo build` or `cargo test`),
//! you must first compile the C++ Centipede dependencies using Bazel (or Blaze):
//!
//! ```bash
//! bazel build //centipede:centipede_engine_static
//! ```
//!
//! This command generates the required static library archive `libcentipede_engine_static.a`
//! under `bazel-bin/centipede` (or `blaze-bin/centipede`).
//!
//! You can provide the directory path containing this library via `FUZZTEST_LIB_PATH`:
//!
//! ```bash
//! FUZZTEST_LIB_PATH="bazel-bin/centipede" cargo build
//! ```

fn main() {
    // Re-run this build script if FUZZTEST_LIB_PATH changes.
    println!("cargo:rerun-if-env-changed=FUZZTEST_LIB_PATH");

    // Add native library search path if FUZZTEST_LIB_PATH is provided.
    if let Ok(lib_dir) = std::env::var("FUZZTEST_LIB_PATH") {
        println!("cargo:rustc-link-search=native={lib_dir}");
    }

    println!("cargo:rustc-link-lib=static=centipede_engine_static");

    // Link required system libraries
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=rt");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=pthread");
}
