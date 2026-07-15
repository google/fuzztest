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

use std::path::{Path, PathBuf};

fn copy_lib(src_dir: &Path, dst_dir: &Path, name: &str, rename_to: Option<&str>) {
    let src_name = format!("lib{}.a", name);
    let dst_name = format!("lib{}.a", rename_to.unwrap_or(name));
    let src_path = src_dir.join(src_name);
    let dst_path = dst_dir.join(dst_name);

    if dst_path.exists() {
        let _ = std::fs::remove_file(&dst_path);
    }

    if let Err(e) = std::fs::copy(&src_path, &dst_path) {
        panic!("Failed to copy {} to {}: {}", src_path.display(), dst_path.display(), e);
    }
}

fn main() {
    println!("cargo:rerun-if-env-changed=CENTIPEDE_BIN_DIR");
    let out_dir = std::env::var("OUT_DIR").map(PathBuf::from).expect("OUT_DIR not set");

    let mut centipede_bin_dir = None;

    // Try environment variable override
    if let Ok(dir) = std::env::var("CENTIPEDE_BIN_DIR") {
        if let Ok(p) = PathBuf::from(dir).canonicalize() {
            centipede_bin_dir = Some(p);
        }
    }

    if let Some(centipede_bin_dir) = centipede_bin_dir {
        copy_lib(&centipede_bin_dir, &out_dir, "centipede_engine_static", None);
        println!("cargo:rustc-link-search=native={}", out_dir.display());
    }

    println!("cargo:rustc-link-lib=static=centipede_engine_static");

    // Link required system libraries
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=rt");
    println!("cargo:rustc-link-lib=dylib=dl");
    println!("cargo:rustc-link-lib=dylib=pthread");
}
