use cargo_fuzztest::{CargoFuzzTestOptions, FuzztestRunner};
use googletest::prelude::*;
use std::env;
use std::path::PathBuf;

#[gtest]
fn test_runner_execution() {
    let binary_path = get_sample_fuzz_test_bin_path();

    assert!(binary_path.exists(), "Sample fuzz binary does not exist at {}", binary_path.display());

    let options = CargoFuzzTestOptions::default();
    let runner = FuzztestRunner::new("sample-host-triple".to_string(), options);

    let mut cmd = runner.build_run_command(&binary_path);

    let status = cmd.status().expect("Failed to execute test binary command");

    expect_true!(status.success());
}

#[gtest]
fn test_runner_list_command() {
    let binary_path = get_sample_fuzz_test_bin_path();

    assert!(binary_path.exists(), "Sample fuzz binary does not exist at {}", binary_path.display());

    let options = CargoFuzzTestOptions { list: true, ..Default::default() };

    let runner = FuzztestRunner::new("sample-host-triple".to_string(), options);

    let cmd = runner.build_run_command(&binary_path);

    let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().to_string()).collect();
    expect_eq!(args, &["__fuzztest_mod__", "--list"]);
}

fn get_sample_fuzz_test_bin_path() -> PathBuf {
    // 1. Cargo test: Check if CARGO_BIN_EXE_<name> is set
    if let Ok(cargo_bin) = env::var("CARGO_BIN_EXE_sample_fuzz_test_bin") {
        return PathBuf::from(cargo_bin);
    }

    // 2. Bazel/Blaze test: Fall back to TEST_SRCDIR and TEST_WORKSPACE
    if let Ok(src_dir) = env::var("TEST_SRCDIR") {
        let test_workspace = env::var("TEST_WORKSPACE").unwrap_or_else(|_| {
            "_main".to_string()
        });

        const RELATIVE_BINARY_PATH: &str =
        "rust/cargo_fuzztest/sample_fuzz_test_bin";

        let blaze_path = PathBuf::from(src_dir).join(test_workspace).join(RELATIVE_BINARY_PATH);
        if blaze_path.exists() {
            return blaze_path;
        }
    }

    // 2. Cargo test fallback: Query compiled test executable path via Cargo JSON compiler messages
    if env::var("CARGO_MANIFEST_DIR").is_ok() {
        let cargo_bin = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let output = std::process::Command::new(cargo_bin)
            .args(["test", "--no-run", "--message-format=json", "--test", "sample_fuzz_test_bin"])
            .output()
            .expect("Failed to execute `cargo test --no-run --message-format=json` to locate test binary");

        if output.status.success() {
            let json_stdout = String::from_utf8_lossy(&output.stdout);
            if let Ok(exe) = FuzztestRunner::parse_compiler_messages(&json_stdout) {
                return exe;
            }
        }
    }

    panic!("Could not locate sample_fuzz_test_bin via CARGO_BIN_EXE, TEST_SRCDIR, or Cargo compiler messages");
}
