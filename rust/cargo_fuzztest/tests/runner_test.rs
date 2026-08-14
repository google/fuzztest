use cargo_fuzztest::{CargoFuzzTestOptions, FuzztestRunner};
use fuzztest_options::{FuzzFor, FuzzTestOptions};
use googletest::prelude::*;
use std::env;
use std::path::PathBuf;

#[gtest]
fn test_runner_execution() {
    let binary_path = get_sample_fuzz_test_bin_path();

    assert!(binary_path.exists(), "Sample fuzz binary does not exist at {}", binary_path.display());

    let options = CargoFuzzTestOptions::default();
    let runner = FuzztestRunner::new("sample-host-triple".to_string(), options);

    let mut cmd = runner
        .build_run_command(&binary_path)
        .expect("building run command in smoke test mode should succeed");

    let status = cmd.status().expect("Failed to execute test binary command");

    expect_true!(status.success());
}

#[gtest]
fn test_runner_build_run_command_with_target() {
    let binary_path = get_sample_fuzz_test_bin_path();
    let options = CargoFuzzTestOptions {
        test_path: Some(
            "__fuzztest_mod__sample_fuzztest_target::sample_fuzztest_target".to_string(),
        ),
        centipede_binary_path: Some("/custom/path/to/centipede".to_string()),
        ..Default::default()
    };
    let runner = FuzztestRunner::new("x86_64-unknown-linux-gnu".to_string(), options);
    let cmd = runner.build_run_command(&binary_path).expect("valid run command");

    let args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
    expect_true!(args
        .contains(&"__fuzztest_mod__sample_fuzztest_target::sample_fuzztest_target".to_string()));
    expect_true!(args.contains(&"--exact".to_string()));
}

#[gtest]
fn test_runner_build_run_command_with_duration() {
    let binary_path = get_sample_fuzz_test_bin_path();
    let fuzztest_options = FuzzTestOptions {
        fuzz_for: Some(FuzzFor::Duration("5s".parse().unwrap())),
        ..Default::default()
    };
    let options = CargoFuzzTestOptions {
        fuzztest_options,
        centipede_binary_path: Some("/custom/path/to/centipede".to_string()),
        ..Default::default()
    };
    let runner = FuzztestRunner::new("x86_64-unknown-linux-gnu".to_string(), options);
    let cmd = runner.build_run_command(&binary_path).expect("valid run command");

    let envs: Vec<(String, Option<String>)> = cmd
        .get_envs()
        .map(|(k, v)| (k.to_string_lossy().to_string(), v.map(|s| s.to_string_lossy().to_string())))
        .collect();
    expect_true!(envs.contains(&("FUZZTEST_FUZZ_FOR".to_string(), Some("5s".to_string()))));
}

#[gtest]
fn test_runner_build_run_command_with_indefinitely() {
    let binary_path = get_sample_fuzz_test_bin_path();
    let fuzztest_options =
        FuzzTestOptions { fuzz_for: Some(FuzzFor::Indefinitely), ..Default::default() };
    let options = CargoFuzzTestOptions {
        fuzztest_options,
        centipede_binary_path: Some("/custom/path/to/centipede".to_string()),
        ..Default::default()
    };
    let runner = FuzztestRunner::new("x86_64-unknown-linux-gnu".to_string(), options);
    let cmd = runner.build_run_command(&binary_path).expect("valid run command");

    let envs: Vec<(String, Option<String>)> = cmd
        .get_envs()
        .map(|(k, v)| (k.to_string_lossy().to_string(), v.map(|s| s.to_string_lossy().to_string())))
        .collect();
    expect_true!(envs.contains(&("FUZZTEST_FUZZ_FOR".to_string(), Some("inf".to_string()))));
}

#[gtest]
fn test_runner_build_run_command_with_centipede_binary_path() {
    let binary_path = get_sample_fuzz_test_bin_path();
    let options = CargoFuzzTestOptions {
        centipede_binary_path: Some("/custom/path/to/centipede".to_string()),
        ..Default::default()
    };
    let runner = FuzztestRunner::new("x86_64-unknown-linux-gnu".to_string(), options);
    let cmd = runner.build_run_command(&binary_path).expect("valid run command");

    let envs: Vec<(String, Option<String>)> = cmd
        .get_envs()
        .map(|(k, v)| (k.to_string_lossy().to_string(), v.map(|s| s.to_string_lossy().to_string())))
        .collect();
    expect_true!(envs.contains(&(
        "FUZZTEST_CENTIPEDE_BINARY_PATH".to_string(),
        Some("/custom/path/to/centipede".to_string())
    )));
}

#[gtest]
fn test_execution_mode_without_centipede_binary_path_errors() {
    let fuzztest_options =
        FuzzTestOptions { fuzz_for: Some(FuzzFor::Indefinitely), ..Default::default() };
    let options = CargoFuzzTestOptions { fuzztest_options, ..Default::default() };
    let result = options.execution_mode();
    expect_true!(result.is_err());
}

#[gtest]
fn test_runner_list_command() {
    let binary_path = get_sample_fuzz_test_bin_path();

    assert!(binary_path.exists(), "Sample fuzz binary does not exist at {}", binary_path.display());

    let options = CargoFuzzTestOptions { list: true, ..Default::default() };

    let runner = FuzztestRunner::new("sample-host-triple".to_string(), options);

    let cmd = runner.build_run_command(&binary_path).expect("should build run command");

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
