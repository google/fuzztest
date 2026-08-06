use cargo_fuzztest::FuzztestRunner;
use googletest::prelude::*;
use std::env;
use std::path::PathBuf;

#[gtest]
fn test_runner_execution() {
    let binary_path = get_dummy_fuzz_test_bin_path();

    assert!(binary_path.exists(), "Dummy fuzz binary does not exist at {}", binary_path.display());

    let runner = FuzztestRunner::new("x86_64-unknown-linux-gnu".to_string());

    let mut cmd = runner.build_run_command(&binary_path);

    let status = cmd.status().expect("Failed to execute test binary command");

    expect_true!(status.success());
}

fn get_dummy_fuzz_test_bin_path() -> PathBuf {
    // 1. Cargo test: Check if CARGO_BIN_EXE_<name> is set
    if let Ok(cargo_bin) = env::var("CARGO_BIN_EXE_dummy_fuzz_test_bin") {
        return PathBuf::from(cargo_bin);
    }

    // 2. Bazel/Blaze test: Fall back to TEST_SRCDIR and TEST_WORKSPACE
    let src_dir = env::var("TEST_SRCDIR")
        .expect("Neither CARGO_BIN_EXE_dummy_fuzz_test_bin nor TEST_SRCDIR is set");
    let test_workspace = env::var("TEST_WORKSPACE").unwrap_or_else(|_| {
        "_main".to_string()
    });

    const RELATIVE_BINARY_PATH: &str =
    "rust/cargo_fuzztest/dummy_fuzz_test_bin";

    PathBuf::from(src_dir).join(test_workspace).join(RELATIVE_BINARY_PATH)
}
