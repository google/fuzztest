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

#![feature(cfg_sanitize)]

mod crash_handler;
pub mod domains;
pub mod internal;
pub mod worker;

pub use fuzztest_macro::fuzztest;
pub use serde;

pub mod options;
pub use options::get_fuzztest_options;
pub use options::FuzzTestOptions;

// Re-export helper crates used in macro expansion to decouple downstream Cargo.toml files.
#[doc(hidden)]
pub mod reexports {
    pub use anyhow;
    pub use inventory;
    pub use rand;
}
