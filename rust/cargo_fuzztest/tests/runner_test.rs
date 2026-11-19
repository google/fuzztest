mod common;

use cargo_fuzztest::{CargoFuzzTestOptions, FuzztestRunner};
use common::get_sample_test_bin_path;
use fuzztest_options::{FuzzTestOptions, RunDuration};
use googletest::prelude::*;

#[gtest]
fn test_runner_execution() {
    let binary_path = get_sample_test_bin_path("sample_fuzz_crate");

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
    let binary_path = get_sample_test_bin_path("sample_fuzz_crate");
    let options = CargoFuzzTestOptions {
        test_path: Some(
            "__fuzztest_mod__sample_fuzztest_target::sample_fuzztest_target".to_string(),
        ),
        centipede_binary_path: Some("/custom/path/to/centipede".to_string()),
        ..Default::default()
    };
    let runner = FuzztestRunner::new("sample-host-triple".to_string(), options);
    let cmd = runner.build_run_command(&binary_path).expect("valid run command");

    let args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
    expect_true!(args
        .contains(&"__fuzztest_mod__sample_fuzztest_target::sample_fuzztest_target".to_string()));
    expect_true!(args.contains(&"--exact".to_string()));
}

#[gtest]
fn test_runner_build_run_command_with_duration() {
    let binary_path = get_sample_test_bin_path("sample_fuzz_crate");
    let fuzztest_options =
        FuzzTestOptions { fuzz_for: Some("5s".parse().unwrap()), ..Default::default() };
    let options = CargoFuzzTestOptions {
        fuzztest_options,
        centipede_binary_path: Some("/custom/path/to/centipede".to_string()),
        ..Default::default()
    };
    let runner = FuzztestRunner::new("sample-host-triple".to_string(), options);
    let cmd = runner.build_run_command(&binary_path).expect("valid run command");

    let envs: Vec<(String, Option<String>)> = cmd
        .get_envs()
        .map(|(k, v)| (k.to_string_lossy().to_string(), v.map(|s| s.to_string_lossy().to_string())))
        .collect();
    expect_true!(envs.contains(&("FUZZTEST_FUZZ_FOR".to_string(), Some("5s".to_string()))));
}

#[gtest]
fn test_runner_build_run_command_with_indefinitely() {
    let binary_path = get_sample_test_bin_path("sample_fuzz_crate");
    let fuzztest_options =
        FuzzTestOptions { fuzz_for: Some(RunDuration::Indefinitely), ..Default::default() };
    let options = CargoFuzzTestOptions {
        fuzztest_options,
        centipede_binary_path: Some("/custom/path/to/centipede".to_string()),
        ..Default::default()
    };
    let runner = FuzztestRunner::new("sample-host-triple".to_string(), options);
    let cmd = runner.build_run_command(&binary_path).expect("valid run command");

    let envs: Vec<(String, Option<String>)> = cmd
        .get_envs()
        .map(|(k, v)| (k.to_string_lossy().to_string(), v.map(|s| s.to_string_lossy().to_string())))
        .collect();
    expect_true!(envs.contains(&("FUZZTEST_FUZZ_FOR".to_string(), Some("inf".to_string()))));
}

#[gtest]
fn test_runner_build_run_command_with_centipede_binary_path() {
    let binary_path = get_sample_test_bin_path("sample_fuzz_crate");
    let options = CargoFuzzTestOptions {
        centipede_binary_path: Some("/custom/path/to/centipede".to_string()),
        ..Default::default()
    };
    let runner = FuzztestRunner::new("sample-host-triple".to_string(), options);
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
fn test_runner_build_run_command_with_jobs() {
    let binary_path = get_sample_test_bin_path("sample_fuzz_crate");
    let fuzztest_options = FuzzTestOptions {
        jobs: Some(4),
        fuzz_for: Some("10s".parse().expect("static valid duration string")),
        ..Default::default()
    };
    let options = CargoFuzzTestOptions {
        fuzztest_options,
        centipede_binary_path: Some("/custom/path/to/centipede".to_string()),
        ..Default::default()
    };
    let runner = FuzztestRunner::new("sample-host-triple".to_string(), options);
    let cmd = runner.build_run_command(&binary_path).expect("valid run command");

    let envs: Vec<(String, Option<String>)> = cmd
        .get_envs()
        .map(|(k, v)| (k.to_string_lossy().to_string(), v.map(|s| s.to_string_lossy().to_string())))
        .collect();
    expect_true!(envs.contains(&("FUZZTEST_JOBS".to_string(), Some("4".to_string()))));
    expect_true!(envs.contains(&("FUZZTEST_FUZZ_FOR".to_string(), Some("10s".to_string()))));
}

#[gtest]
fn test_runner_build_run_command_with_jobs_only() {
    let binary_path = get_sample_test_bin_path("sample_fuzz_crate");
    let fuzztest_options = FuzzTestOptions { jobs: Some(4), ..Default::default() };
    let options = CargoFuzzTestOptions { fuzztest_options, ..Default::default() };
    let runner = FuzztestRunner::new("sample-host-triple".to_string(), options);
    let cmd = runner.build_run_command(&binary_path).expect("valid run command");

    let envs: Vec<(String, Option<String>)> = cmd
        .get_envs()
        .map(|(k, v)| (k.to_string_lossy().to_string(), v.map(|s| s.to_string_lossy().to_string())))
        .collect();
    expect_false!(envs.iter().any(|(k, _)| k == "FUZZTEST_JOBS"));
    expect_false!(envs.iter().any(|(k, _)| k == "FUZZTEST_FUZZ_FOR"));
}
