mod common;

use cargo_fuzztest::{CargoFuzzTestOptions, FuzztestRunner};
use common::get_dummy_test_bin_path;
use fuzztest_options::{FuzzFor, FuzzTestOptions};
use googletest::prelude::*;

#[gtest]
fn test_runner_execution() {
    let binary_path = get_dummy_test_bin_path("dummy_fuzz_crate");

    assert!(binary_path.exists(), "Dummy fuzz binary does not exist at {}", binary_path.display());

    let runner = FuzztestRunner::new(
        "x86_64-unknown-linux-gnu".to_string(),
        CargoFuzzTestOptions::default(),
    );

    let mut cmd = runner
        .build_run_command(&binary_path)
        .expect("building run command in smoke test mode should succeed");

    eprintln!("tmp:: cmd: {:?}", cmd);

    let status = cmd.status().expect("Failed to execute test binary command");

    expect_true!(status.success());
}

#[gtest]
fn test_runner_build_run_command_with_target() {
    let binary_path = get_dummy_test_bin_path("dummy_fuzz_crate");
    let options = CargoFuzzTestOptions {
        test_path: Some("__fuzztest_mod__dummy_fuzztest_target::dummy_fuzztest_target".to_string()),
        centipede_binary_path: Some("/custom/path/to/centipede".to_string()),
        ..Default::default()
    };
    let runner = FuzztestRunner::new("x86_64-unknown-linux-gnu".to_string(), options);
    let cmd = runner.build_run_command(&binary_path).expect("valid run command");

    let args: Vec<String> = cmd.get_args().map(|s| s.to_string_lossy().to_string()).collect();
    expect_true!(
        args.contains(&"__fuzztest_mod__dummy_fuzztest_target::dummy_fuzztest_target".to_string())
    );
    expect_true!(args.contains(&"--exact".to_string()));
}

#[gtest]
fn test_runner_build_run_command_with_duration() {
    let binary_path = get_dummy_test_bin_path("dummy_fuzz_crate");
    let fuzztest_options = FuzzTestOptions {
        fuzz_for: Some(FuzzFor::Duration("5s".parse().expect("valid duration"))),
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
    let binary_path = get_dummy_test_bin_path("dummy_fuzz_crate");
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
fn test_runner_build_run_command_with_jobs() {
    let binary_path = get_dummy_test_bin_path("dummy_fuzz_crate");
    let fuzztest_options = FuzzTestOptions {
        jobs: Some(4),
        fuzz_for: Some(FuzzFor::Duration("10s".parse().expect("static valid duration string"))),
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
    expect_true!(envs.contains(&("FUZZTEST_JOBS".to_string(), Some("4".to_string()))));
    expect_true!(envs.contains(&("FUZZTEST_FUZZ_FOR".to_string(), Some("10s".to_string()))));
}

#[gtest]
fn test_runner_build_run_command_with_jobs_only() {
    let binary_path = get_dummy_test_bin_path("dummy_fuzz_crate");
    let fuzztest_options = FuzzTestOptions { jobs: Some(4), ..Default::default() };
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
    expect_true!(envs.contains(&("FUZZTEST_JOBS".to_string(), Some("4".to_string()))));
    expect_true!(envs.contains(&("FUZZTEST_FUZZ_FOR".to_string(), Some("inf".to_string()))));
}

#[gtest]
fn test_runner_build_run_command_with_replay_id() {
    let binary_path = get_dummy_test_bin_path("dummy_fuzz_crate");
    let fuzztest_options = FuzzTestOptions {
        replay_id: Some("crash_12345".to_string()),
        corpus_db: Some("/custom/path/to/corpus_db".to_string()),
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
    expect_true!(
        envs.contains(&("FUZZTEST_REPLAY_ID".to_string(), Some("crash_12345".to_string())))
    );
    expect_true!(envs.contains(&(
        "FUZZTEST_CORPUS_DB".to_string(),
        Some("/custom/path/to/corpus_db".to_string())
    )));
    expect_true!(envs.contains(&(
        "FUZZTEST_CENTIPEDE_BINARY_PATH".to_string(),
        Some("/custom/path/to/centipede".to_string())
    )));
}

#[gtest]
fn test_execution_mode_replay_id_missing_corpus_db_errors() {
    let fuzztest_options =
        FuzzTestOptions { replay_id: Some("crash_12345".to_string()), ..Default::default() };
    let options = CargoFuzzTestOptions {
        fuzztest_options,
        centipede_binary_path: Some("/custom/path/to/centipede".to_string()),
        ..Default::default()
    };
    let result = options.execution_mode();
    expect_true!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    expect_true!(err_msg.contains("`--corpus-db` needs to be specified"));
}

#[gtest]
fn test_execution_mode_replay_id_missing_centipede_binary_path_errors() {
    let fuzztest_options = FuzzTestOptions {
        replay_id: Some("crash_12345".to_string()),
        corpus_db: Some("/custom/path/to/corpus_db".to_string()),
        ..Default::default()
    };
    let options = CargoFuzzTestOptions { fuzztest_options, ..Default::default() };
    let result = options.execution_mode();
    expect_true!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    expect_true!(err_msg.contains("`--centipede-binary-path` needs to be specified"));
}

#[gtest]
fn test_runner_build_run_command_with_replay_findings() {
    let binary_path = get_dummy_test_bin_path("dummy_fuzz_crate");
    let fuzztest_options = FuzzTestOptions {
        replay_findings: true,
        corpus_db: Some("/custom/path/to/corpus_db".to_string()),
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
    expect_true!(envs.contains(&("FUZZTEST_REPLAY_FINDINGS".to_string(), Some("true".to_string()))));
    expect_true!(envs.contains(&(
        "FUZZTEST_CORPUS_DB".to_string(),
        Some("/custom/path/to/corpus_db".to_string())
    )));
    expect_true!(envs.contains(&(
        "FUZZTEST_CENTIPEDE_BINARY_PATH".to_string(),
        Some("/custom/path/to/centipede".to_string())
    )));
}

#[gtest]
fn test_execution_mode_replay_findings_missing_centipede_binary_path_errors() {
    let fuzztest_options = FuzzTestOptions {
        replay_findings: true,
        corpus_db: Some("/custom/path/to/corpus_db".to_string()),
        ..Default::default()
    };
    let options = CargoFuzzTestOptions { fuzztest_options, ..Default::default() };
    let result = options.execution_mode();
    expect_true!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    expect_true!(err_msg.contains("`--centipede-binary-path` needs to be specified"));
}

#[gtest]
fn test_runner_list_command() {
    let binary_path = get_dummy_test_bin_path("dummy_fuzz_crate");

    assert!(binary_path.exists(), "Dummy fuzz binary does not exist at {}", binary_path.display());

    let options = CargoFuzzTestOptions { list: true, ..Default::default() };

    let runner = FuzztestRunner::new("x86_64-unknown-linux-gnu".to_string(), options);

    let cmd = runner.build_run_command(&binary_path).expect("should build run command");

    let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().to_string()).collect();
    expect_eq!(args, vec!["__fuzztest_mod__", "--list"]);
}
