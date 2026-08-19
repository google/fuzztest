mod common;

use cargo_fuzztest::{CargoFuzzTestOptions, FuzztestRunner};
use common::get_sample_test_bin_path;
use fuzztest_options::{FuzzTestOptions, RunDuration, TimeBudgetType};
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

#[gtest]
fn test_runner_build_run_command_with_replay_id() {
    let binary_path = get_sample_test_bin_path("sample_fuzz_crate");
    let fuzztest_options = FuzzTestOptions {
        replay_id: Some("crash_12345".to_string()),
        corpus_db: Some("/custom/path/to/corpus_db".into()),
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
        corpus_db: Some("/custom/path/to/corpus_db".into()),
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
    let binary_path = get_sample_test_bin_path("sample_fuzz_crate");
    let fuzztest_options = FuzzTestOptions {
        replay_findings: true,
        corpus_db: Some("/custom/path/to/corpus_db".into()),
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
        corpus_db: Some("/custom/path/to/corpus_db".into()),
        ..Default::default()
    };
    let options = CargoFuzzTestOptions { fuzztest_options, ..Default::default() };
    let result = options.execution_mode();
    expect_true!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    expect_true!(err_msg.contains("`--centipede-binary-path` needs to be specified"));
}

#[gtest]
fn test_runner_build_run_command_with_replay_corpus() {
    let binary_path = get_sample_test_bin_path("sample_fuzz_crate");
    let fuzztest_options = FuzzTestOptions {
        replay_corpus_for: Some("10s".parse().expect("valid duration")),
        time_budget_type: TimeBudgetType::Total,
        corpus_db: Some("/custom/path/to/corpus_db".into()),
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
    expect_true!(
        envs.contains(&("FUZZTEST_REPLAY_CORPUS_FOR".to_string(), Some("10s".to_string())))
    );
    expect_true!(
        envs.contains(&("FUZZTEST_TIME_BUDGET_TYPE".to_string(), Some("total".to_string())))
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
fn test_runner_build_run_command_with_replay_corpus_indefinitely() {
    let binary_path = get_sample_test_bin_path("sample_fuzz_crate");
    let fuzztest_options = FuzzTestOptions {
        replay_corpus_for: Some(RunDuration::Indefinitely),
        time_budget_type: TimeBudgetType::Total,
        corpus_db: Some("/custom/path/to/corpus_db".into()),
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
    expect_true!(
        envs.contains(&("FUZZTEST_REPLAY_CORPUS_FOR".to_string(), Some("inf".to_string())))
    );
    expect_true!(
        envs.contains(&("FUZZTEST_TIME_BUDGET_TYPE".to_string(), Some("total".to_string())))
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
fn test_execution_mode_replay_corpus_missing_centipede_binary_path_errors() {
    let fuzztest_options = FuzzTestOptions {
        replay_corpus_for: Some("10s".parse().expect("valid duration")),
        corpus_db: Some("/custom/path/to/corpus_db".into()),
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
    let binary_path = get_sample_test_bin_path("sample_fuzz_crate");

    assert!(binary_path.exists(), "Sample fuzz binary does not exist at {}", binary_path.display());

    let options = CargoFuzzTestOptions { list: true, ..Default::default() };

    let runner = FuzztestRunner::new("sample-host-triple".to_string(), options);

    let cmd = runner.build_run_command(&binary_path).expect("should build run command");

    let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().to_string()).collect();
    expect_eq!(args, &["__fuzztest_mod__", "--list"]);
}

#[gtest]
fn test_runner_build_run_command_with_list_crash_ids() {
    let binary_path = get_sample_test_bin_path("sample_fuzz_crate");
    let fuzztest_options = FuzzTestOptions {
        list_crash_ids: true,
        list_crash_ids_file: Some("/custom/path/to/crash_ids.txt".to_string()),
        corpus_db: Some("/custom/path/to/corpus_db".into()),
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
    expect_true!(envs.contains(&("FUZZTEST_LIST_CRASH_IDS".to_string(), Some("true".to_string()))));
    expect_true!(envs.contains(&(
        "FUZZTEST_LIST_CRASH_IDS_FILE".to_string(),
        Some("/custom/path/to/crash_ids.txt".to_string())
    )));
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
fn test_execution_mode_list_crash_ids_missing_corpus_db_errors() {
    let fuzztest_options = FuzzTestOptions {
        list_crash_ids: true,
        list_crash_ids_file: Some("/custom/path/to/crash_ids.txt".to_string()),
        ..Default::default()
    };
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
fn test_execution_mode_list_crash_ids_missing_centipede_binary_path_errors() {
    let fuzztest_options = FuzzTestOptions {
        list_crash_ids: true,
        list_crash_ids_file: Some("/custom/path/to/crash_ids.txt".to_string()),
        corpus_db: Some("/custom/path/to/corpus_db".into()),
        ..Default::default()
    };
    let options = CargoFuzzTestOptions { fuzztest_options, ..Default::default() };
    let result = options.execution_mode();
    expect_true!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    expect_true!(err_msg.contains("`--centipede-binary-path` needs to be specified"));
}
