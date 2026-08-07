use googletest::prelude::*;
use std::env;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

#[gtest]
fn test_cargo_fuzztest_e2e_smoke_test() {
    // Locate the cargo-fuzztest CLI binary compiled by Cargo
    let cargo_fuzztest_bin = env!("CARGO_BIN_EXE_cargo-fuzztest");
    assert!(Path::new(cargo_fuzztest_bin).exists());

    // Resolve the absolute path of the dummy crate
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dummy_crate_path = Path::new(manifest_dir).join("test_crates/dummy_fuzz_crate");
    assert!(dummy_crate_path.exists());

    // Create a temporary directory for Cargo build outputs
    let temp_target_dir = TempDir::new().expect("Failed to create temporary target directory");

    // Invoke: `cargo-fuzztest` inside the resolved dummy crate directory.
    // We capture the output of the process instead of letting it inherit by default.
    let output = Command::new(cargo_fuzztest_bin)
        .current_dir(&dummy_crate_path)
        .env("CARGO_TARGET_DIR", temp_target_dir.path())
        .output()
        .expect("Failed to run cargo-fuzztest command");

    // If the run failed, print the stdout and stderr to the test runner output
    if !output.status.success() {
        eprintln!("\n=================== cargo-fuzztest STDOUT ===================");
        eprintln!("{}", String::from_utf8_lossy(&output.stdout));
        eprintln!("=============================================================");

        eprintln!("\n=================== cargo-fuzztest STDERR ===================");
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        eprintln!("=============================================================\n");
    }

    // Verify the execution completed successfully
    expect_true!(output.status.success());

    // Verify that both fuzztest targets in the crate were run in smoke-test mode
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    expect_true!(stdout_str.contains("dummy_fuzztest_target"));
    expect_true!(stdout_str.contains("another_dummy_fuzztest_target"));
}
