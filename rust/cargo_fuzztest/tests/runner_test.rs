use cargo_fuzztest::FuzztestRunner;
use fuzztest_options::{FuzzFor, FuzzTestOptions};
use googletest::prelude::*;
use std::env;
use std::path::PathBuf;

#[gtest]
fn test_runner_execution() {
    let binary_path = get_dummy_fuzz_test_bin_path();

    assert!(binary_path.exists(), "Dummy fuzz binary does not exist at {}", binary_path.display());

    let runner =
        FuzztestRunner::new("x86_64-unknown-linux-gnu".to_string(), FuzzTestOptions::default());

    let mut cmd = runner.build_run_command(&binary_path);

    let status = cmd.status().expect("Failed to execute test binary command");

    expect_true!(status.success());
}

#[gtest]
fn test_runner_build_run_command_with_target() {
    let binary_path = get_dummy_fuzz_test_bin_path();
    let options = FuzzTestOptions {
        test_path: Some("__fuzztest_mod__dummy_fuzztest_target::dummy_fuzztest_target".to_string()),
        ..Default::default()
    };
    let runner = FuzztestRunner::new("x86_64-unknown-linux-gnu".to_string(), options);
    let cmd = runner.build_run_command(&binary_path);

    let args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
    expect_true!(
        args.contains(&"__fuzztest_mod__dummy_fuzztest_target::dummy_fuzztest_target".to_string())
    );
    expect_true!(args.contains(&"--exact".to_string()));
}

#[gtest]
fn test_runner_build_run_command_with_duration() {
    let binary_path = get_dummy_fuzz_test_bin_path();
    let options = FuzzTestOptions {
        fuzz_for: Some(FuzzFor::Duration("5s".parse().expect("valid duration"))),
        ..Default::default()
    };
    let runner = FuzztestRunner::new("x86_64-unknown-linux-gnu".to_string(), options);
    let cmd = runner.build_run_command(&binary_path);

    let envs: Vec<(String, Option<String>)> = cmd
        .get_envs()
        .map(|(k, v)| (k.to_string_lossy().to_string(), v.map(|s| s.to_string_lossy().to_string())))
        .collect();
    expect_true!(envs.contains(&("FUZZTEST_FUZZ_FOR".to_string(), Some("5s".to_string()))));
}

#[gtest]
fn test_runner_build_run_command_with_indefinitely() {
    let binary_path = get_dummy_fuzz_test_bin_path();
    let options = FuzzTestOptions { fuzz_for: Some(FuzzFor::Indefinitely), ..Default::default() };
    let runner = FuzztestRunner::new("x86_64-unknown-linux-gnu".to_string(), options);
    let cmd = runner.build_run_command(&binary_path);

    let envs: Vec<(String, Option<String>)> = cmd
        .get_envs()
        .map(|(k, v)| (k.to_string_lossy().to_string(), v.map(|s| s.to_string_lossy().to_string())))
        .collect();
    expect_true!(envs.contains(&("FUZZTEST_FUZZ_FOR".to_string(), Some("inf".to_string()))));
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
