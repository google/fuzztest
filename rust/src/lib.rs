#![deny(clippy::absolute_paths)]
#![deny(unused_imports)]
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
