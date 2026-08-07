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
//! You must provide the path to this library via `RUSTFLAGS` when running Cargo:
//!
//! ```bash
//! CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-L bazel-bin/centipede" cargo build
//! ```

fn main() {
    println!("cargo:rustc-link-lib=static=centipede_engine_static");

    // Link required system libraries
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=rt");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=pthread");
}
