// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
