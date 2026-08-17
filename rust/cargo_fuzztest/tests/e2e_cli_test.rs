use googletest::prelude::*;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;

fn setup_cargo_fuzztest_command(project_dir: &Path, temp_target_dir: &Path) -> Command {
    // Locate the cargo-fuzztest CLI binary compiled by Cargo for this integration test
    let binary_path = PathBuf::from(env!("CARGO_BIN_EXE_cargo-fuzztest"));
    assert!(binary_path.exists(), "cargo-fuzztest binary must exist");

    // Prepend the directory containing cargo-fuzztest to PATH so `cargo fuzztest` resolves to it
    let orig_path = env::var("PATH").unwrap_or_default();
    let bin_dir = binary_path.parent().expect("Binary path should have parent directory");
    let new_path = format!("{}:{}", bin_dir.display(), orig_path);

    let cargo_bin = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(cargo_bin);
    cmd.arg("fuzztest");
    cmd.current_dir(project_dir);
    cmd.env("CARGO_TARGET_DIR", temp_target_dir);
    cmd.env("PATH", new_path);
    cmd
}

fn get_sample_crate_path(sample_crate_name: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let sample_crate_path = Path::new(manifest_dir).join("test_crates").join(sample_crate_name);
    assert!(sample_crate_path.exists());
    sample_crate_path
}

#[gtest]
fn test_cargo_fuzztest_e2e_smoke_test() {
    // Resolve the absolute path of the sample crate
    let sample_crate_path = get_sample_crate_path("sample_fuzz_crate");

    // Create a temporary directory for Cargo build outputs
    let temp_target_dir = TempDir::new().expect("Failed to create temporary target directory");

    // Invoke: `cargo fuzztest` inside the resolved sample crate directory.
    let output = setup_cargo_fuzztest_command(&sample_crate_path, temp_target_dir.path())
        .output()
        .expect("Failed to run cargo-fuzztest command");

    // Verify that both fuzztest targets in the crate were run in smoke-test mode
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    expect_true!(stdout_str.contains("sample_fuzztest_target"));
    expect_true!(stdout_str.contains("another_sample_fuzztest_target"));
}

#[gtest]
fn test_cargo_fuzztest_e2e_list() {
    // Resolve the absolute path of the sample crate
    let sample_crate_path = get_sample_crate_path("sample_fuzz_crate");

    let temp_target_dir = TempDir::new().expect("Failed to create temporary target directory");

    // Invoke: `cargo-fuzztest --list` inside the sample crate directory
    let output = setup_cargo_fuzztest_command(&sample_crate_path, temp_target_dir.path())
        .arg("--list")
        .output()
        .expect("Failed to run cargo-fuzztest --list command");

    // Verify execution completed successfully
    expect_true!(output.status.success());

    // Verify that full test paths were listed in stdout
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    expect_true!(
        stdout_str.contains("__fuzztest_mod__sample_fuzztest_target::sample_fuzztest_target")
    );
    expect_true!(stdout_str.contains(
        "__fuzztest_mod__another_sample_fuzztest_target::another_sample_fuzztest_target"
    ));
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    expect_true!(stdout_str.contains("sample_fuzztest_target"));
    expect_true!(stdout_str.contains("another_sample_fuzztest_target"));
}

#[gtest]
fn test_cargo_fuzztest_e2e_specific_target() {
    // Resolve the absolute path of the sample crate
    let sample_crate_path = get_sample_crate_path("sample_fuzz_crate");

    let temp_target_dir = TempDir::new().expect("Failed to create temporary target directory");

    let mut cmd = setup_cargo_fuzztest_command(&sample_crate_path, temp_target_dir.path());

    let centipede_bin = env::var("FUZZTEST_CENTIPEDE_BINARY_PATH")
        .expect("FUZZTEST_CENTIPEDE_BINARY_PATH needs to be set for the test");

    cmd.arg("__fuzztest_mod__sample_fuzztest_target::sample_fuzztest_target")
        .arg("--fuzz-for=2s")
        .env_remove("FUZZTEST_CENTIPEDE_BINARY_PATH")
        .arg("--centipede-binary-path")
        .arg(centipede_bin);

    let output = cmd.output().expect("Failed to run cargo-fuzztest command");

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    expect_true!(stdout_str.contains("sample_fuzztest_target"));
    expect_false!(stdout_str.contains("another_sample_fuzztest_target"));
}

#[gtest]
fn test_cargo_fuzztest_e2e_parallel_jobs() {
    let sample_crate_path = get_sample_crate_path("sample_fuzz_crate");

    let temp_target_dir = TempDir::new().expect("Failed to create temporary target directory");

    let centipede_bin = env::var("FUZZTEST_CENTIPEDE_BINARY_PATH")
        .expect("FUZZTEST_CENTIPEDE_BINARY_PATH needs to be set for the test");

    let mut cmd = setup_cargo_fuzztest_command(&sample_crate_path, temp_target_dir.path());
    cmd.arg("__fuzztest_mod__jobs_test::jobs_test")
        .arg("--jobs")
        .arg("4")
        .arg("--fuzz-for")
        .arg("5s")
        .env_remove("FUZZTEST_CENTIPEDE_BINARY_PATH")
        .arg("--centipede-binary-path")
        .arg(centipede_bin)
        .env("FUZZTEST_PRINT_SUBPROCESS_LOG", "true");

    let output = cmd.output().expect("running local cargo-fuzztest sub-process should complete");

    expect_true!(output.status.success());

    let stderr_str = String::from_utf8_lossy(&output.stderr);
    use std::collections::HashSet;
    let mut pids = HashSet::new();
    for line in stderr_str.lines() {
        if let Some(pos) = line.find("LOG: JOBS_TEST_PID: ") {
            let pid_str = &line[pos + "LOG: JOBS_TEST_PID: ".len()..];
            if let Ok(pid) = pid_str.parse::<u32>() {
                pids.insert(pid);
            }
        }
    }
    expect_that!(pids.len(), eq(4));
}

#[gtest]
fn test_cargo_fuzztest_e2e_replay_by_id() {
    let sample_crate_path = get_sample_crate_path("another_sample_fuzz_crate");

    let temp_target_dir = TempDir::new().expect("Failed to create temporary target directory");
    fs::create_dir_all(&temp_target_dir).expect("Failed to corpus db directory");

    let temp_db_dir = TempDir::new().expect("Failed to create temporary corpus db directory");
    fs::create_dir_all(&temp_db_dir).expect("Failed to corpus db directory");

    let workdir_root_dir =
        TempDir::new().expect("Failed to create temporary workdir_root directory");
    fs::create_dir_all(&workdir_root_dir).expect("Failed to workdir_root directory");

    let centipede_bin = env::var("FUZZTEST_CENTIPEDE_BINARY_PATH")
        .expect("FUZZTEST_CENTIPEDE_BINARY_PATH needs to be set for the test");

    let test_target = "__fuzztest_mod__crashing_fuzztest_target::crashing_fuzztest_target";

    // 1. Run Centipede via cargo-fuzztest to fuzz the target and populate the corpus database.
    let mut cmd = setup_cargo_fuzztest_command(&sample_crate_path, temp_target_dir.path());
    cmd.arg(test_target)
        .arg("--fuzz-for=5s")
        .env_remove("FUZZTEST_CENTIPEDE_BINARY_PATH")
        .arg("--centipede-binary-path")
        .arg(&centipede_bin)
        .arg("--corpus-db")
        .arg(temp_db_dir.path())
        .arg("--workdir-root")
        .arg(workdir_root_dir.path());

    let output = cmd.output().expect("Failed to run cargo-fuzztest to fuzz target");
    assert!(output.status.success());

    // 2. Get list of crash ids via cargo-fuzztest --list-crash-ids
    let list_temp_dir = TempDir::new().expect("Failed to create temporary list directory");
    let crash_ids_file = list_temp_dir.path().join("crash_ids.txt");

    let mut cmd = setup_cargo_fuzztest_command(&sample_crate_path, temp_target_dir.path());
    cmd.arg(test_target)
        .arg("--list-crash-ids")
        .arg("--list-crash-ids-file")
        .arg(&crash_ids_file)
        .arg("--corpus-db")
        .arg(temp_db_dir.path())
        .arg("--centipede-binary-path")
        .arg(&centipede_bin);

    let output = cmd.output().expect("Failed to run cargo-fuzztest to list crash IDs");
    assert!(output.status.success());

    let crash_ids_contents =
        fs::read_to_string(&crash_ids_file).expect("Failed to read crash IDs file");
    let crash_ids: Vec<&str> =
        crash_ids_contents.lines().filter(|line| !line.trim().is_empty()).collect();

    expect_true!(!crash_ids.is_empty());
    let crash_id = crash_ids[0];

    // 3. Run cargo-fuzztest CLI with --replay-id <crash_id> to verify it replays the crash.
    let mut cmd = setup_cargo_fuzztest_command(&sample_crate_path, temp_target_dir.path());
    cmd.arg(test_target)
        .arg("--replay-id")
        .arg(crash_id)
        .arg("--corpus-db")
        .arg(temp_db_dir.path())
        .arg("--workdir-root")
        .arg(workdir_root_dir.path())
        .arg("--centipede-binary-path")
        .arg(&centipede_bin);

    let output = cmd.output().expect("Failed to run cargo-fuzztest in replay mode");

    let stderr_str = String::from_utf8_lossy(&output.stderr);
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    expect_false!(output.status.success());
    expect_true!(
        stderr_str.contains("FuzzTest controller reported failure")
            || stderr_str.contains("Crashing bug found!")
            || stdout_str.contains("FuzzTest controller reported failure")
    );
}

#[gtest]
fn test_cargo_fuzztest_e2e_replay_all_crashes() {
    let centipede_bin = env::var("FUZZTEST_CENTIPEDE_BINARY_PATH")
        .expect("FUZZTEST_CENTIPEDE_BINARY_PATH needs to be provided");

    let sample_crate_path = get_sample_crate_path("another_sample_fuzz_crate");

    let temp_target_dir = TempDir::new().expect("Failed to create temporary target directory");
    fs::create_dir_all(&temp_target_dir).expect("Failed to create target directory");

    let temp_db_dir = TempDir::new().expect("Failed to create temporary corpus db directory");
    fs::create_dir_all(&temp_db_dir).expect("Failed to create corpus db directory");

    let workdir_root_dir =
        TempDir::new().expect("Failed to create temporary workdir_root directory");
    fs::create_dir_all(&workdir_root_dir).expect("Failed to create workdir_root directory");

    let test_target = "__fuzztest_mod__crashing_fuzztest_target::crashing_fuzztest_target";

    // 1. Run Centipede via cargo-fuzztest to fuzz the target and populate the corpus database.
    let mut cmd = setup_cargo_fuzztest_command(&sample_crate_path, temp_target_dir.path());
    cmd.arg(test_target)
        .arg("--fuzz-for=5s")
        .env_remove("FUZZTEST_CENTIPEDE_BINARY_PATH")
        .arg("--centipede-binary-path")
        .arg(&centipede_bin)
        .arg("--corpus-db")
        .arg(temp_db_dir.path())
        .arg("--workdir-root")
        .arg(workdir_root_dir.path());
    let output = cmd.output().expect("Failed to run cargo-fuzztest to fuzz target");
    assert!(output.status.success());

    // 2. Run cargo-fuzztest CLI with --replay-findings to verify it replays all crashes from corpus db.
    let mut cmd = setup_cargo_fuzztest_command(&sample_crate_path, temp_target_dir.path());
    cmd.arg(test_target)
        .arg("--replay-findings")
        .arg("--corpus-db")
        .arg(temp_db_dir.path())
        .arg("--centipede-binary-path")
        .arg(&centipede_bin);

    let output = cmd.output().expect("Failed to run cargo-fuzztest in replay-findings mode");

    let stderr_str = String::from_utf8_lossy(&output.stderr);
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    expect_true!(output.status.success());
    expect_true!(
        stderr_str.contains("Crashing bug found!") || stdout_str.contains("Crashing bug found!")
    );
}

#[gtest]
fn test_cargo_fuzztest_e2e_replay_corpus() {
    let centipede_bin = env::var("FUZZTEST_CENTIPEDE_BINARY_PATH")
        .expect("FUZZTEST_CENTIPEDE_BINARY_PATH needs to be provided");

    let sample_crate_path = get_sample_crate_path("sample_fuzz_crate");

    let temp_target_dir = TempDir::new().expect("Failed to create temporary target directory");
    fs::create_dir_all(&temp_target_dir).expect("Failed to create target directory");

    let temp_db_dir = TempDir::new().expect("Failed to create temporary corpus db directory");
    fs::create_dir_all(&temp_db_dir).expect("Failed to create corpus db directory");

    let workdir_root_dir =
        TempDir::new().expect("Failed to create temporary workdir_root directory");
    fs::create_dir_all(&workdir_root_dir).expect("Failed to create workdir_root directory");

    // 1. Run Centipede via cargo-fuzztest to fuzz and populate the corpus database.
    let mut cmd = setup_cargo_fuzztest_command(&sample_crate_path, temp_target_dir.path());
    cmd.arg("__fuzztest_mod__sample_fuzztest_target::sample_fuzztest_target")
        .arg("--fuzz-for=3s")
        .env_remove("FUZZTEST_CENTIPEDE_BINARY_PATH")
        .arg("--centipede-binary-path")
        .arg(&centipede_bin)
        .arg("--corpus-db")
        .arg(temp_db_dir.path())
        .arg("--workdir-root")
        .arg(workdir_root_dir.path());
    let output = cmd.output().expect("Failed to run cargo-fuzztest to fuzz target");
    assert!(output.status.success());

    // 2. Run cargo-fuzztest CLI with --replay-corpus-for to verify it replays the corpus.
    let mut cmd = setup_cargo_fuzztest_command(&sample_crate_path, temp_target_dir.path());
    cmd.arg("__fuzztest_mod__sample_fuzztest_target::sample_fuzztest_target")
        .arg("--replay-corpus-for=2s")
        .arg("--corpus-db")
        .arg(temp_db_dir.path())
        .arg("--centipede-binary-path")
        .arg(&centipede_bin);

    let output = cmd.output().expect("Failed to run cargo-fuzztest in replay-corpus mode");
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    let stdout_str = String::from_utf8_lossy(&output.stdout);

    expect_true!(output.status.success());
    expect_true!(
        stderr_str.contains(
            "Replaying __fuzztest_mod__sample_fuzztest_target.sample_fuzztest_target for 2s"
        ) || stdout_str.contains(
            "Replaying __fuzztest_mod__sample_fuzztest_target.sample_fuzztest_target for 2s"
        )
    );
}

#[gtest]
fn test_cargo_fuzztest_e2e_replay_corpus_total_budget() {
    let centipede_bin = env::var("FUZZTEST_CENTIPEDE_BINARY_PATH")
        .expect("FUZZTEST_CENTIPEDE_BINARY_PATH needs to be provided");

    let sample_crate_path = get_sample_crate_path("sample_fuzz_crate");

    let temp_target_dir = TempDir::new().expect("Failed to create temporary target directory");
    fs::create_dir_all(&temp_target_dir).expect("Failed to create target directory");

    let temp_db_dir = TempDir::new().expect("Failed to create temporary corpus db directory");
    fs::create_dir_all(&temp_db_dir).expect("Failed to create corpus db directory");

    let workdir_root_dir =
        TempDir::new().expect("Failed to create temporary workdir_root directory");
    fs::create_dir_all(&workdir_root_dir).expect("Failed to create workdir_root directory");

    // 1. Run Centipede via cargo-fuzztest to fuzz and populate the corpus database.
    let mut cmd = setup_cargo_fuzztest_command(&sample_crate_path, temp_target_dir.path());
    cmd.arg("__fuzztest_mod__sample_fuzztest_target::sample_fuzztest_target")
        .arg("--fuzz-for=3s")
        .env_remove("FUZZTEST_CENTIPEDE_BINARY_PATH")
        .arg("--centipede-binary-path")
        .arg(&centipede_bin)
        .arg("--corpus-db")
        .arg(temp_db_dir.path())
        .arg("--workdir-root")
        .arg(workdir_root_dir.path());
    let output = cmd.output().expect("Failed to run cargo-fuzztest to fuzz target");
    assert!(output.status.success());

    // 2. Run cargo-fuzztest CLI with --replay-corpus-for and --time-budget-type total.
    let mut cmd = setup_cargo_fuzztest_command(&sample_crate_path, temp_target_dir.path());
    cmd.arg("__fuzztest_mod__sample_fuzztest_target::sample_fuzztest_target")
        .arg("--replay-corpus-for=3s")
        .arg("--time-budget-type=total")
        .arg("--corpus-db")
        .arg(temp_db_dir.path())
        .arg("--centipede-binary-path")
        .arg(&centipede_bin);

    let output = cmd.output().expect("Failed to run cargo-fuzztest in replay-corpus mode");
    let stderr_str = String::from_utf8_lossy(&output.stderr);
    let stdout_str = String::from_utf8_lossy(&output.stdout);

    expect_true!(output.status.success());
    expect_true!(
        stderr_str.contains(
            "Replaying __fuzztest_mod__sample_fuzztest_target.sample_fuzztest_target for 1s"
        ) || stdout_str.contains(
            "Replaying __fuzztest_mod__sample_fuzztest_target.sample_fuzztest_target for 1s"
        )
    );
}

#[gtest]
fn test_cargo_fuzztest_e2e_list_crash_ids() {
    let centipede_bin = env::var("FUZZTEST_CENTIPEDE_BINARY_PATH")
        .expect("FUZZTEST_CENTIPEDE_BINARY_PATH needs to be provided");

    let sample_crate_path = get_sample_crate_path("another_sample_fuzz_crate");

    let temp_target_dir = TempDir::new().expect("Failed to create temporary target directory");
    fs::create_dir_all(&temp_target_dir).expect("Failed to create target directory");

    let temp_db_dir = TempDir::new().expect("Failed to create temporary corpus db directory");
    fs::create_dir_all(&temp_db_dir).expect("Failed to create corpus db directory");

    let workdir_root_dir =
        TempDir::new().expect("Failed to create temporary workdir_root directory");
    fs::create_dir_all(&workdir_root_dir).expect("Failed to create workdir_root directory");

    let test_target = "__fuzztest_mod__crashing_fuzztest_target::crashing_fuzztest_target";

    // 1. Run Centipede via cargo-fuzztest to fuzz the target and populate the corpus database.
    let mut cmd = setup_cargo_fuzztest_command(&sample_crate_path, temp_target_dir.path());
    cmd.arg(test_target)
        .arg("--fuzz-for=5s")
        .env_remove("CENTIPEDE_BINARY_PATH")
        .arg("--centipede-binary-path")
        .arg(&centipede_bin)
        .arg("--corpus-db")
        .arg(temp_db_dir.path())
        .arg("--workdir-root")
        .arg(workdir_root_dir.path());
    let output = cmd.output().expect("Failed to run cargo-fuzztest to fuzz target");
    assert!(output.status.success());

    // 2. Run cargo-fuzztest CLI with --list-crash-ids and --list-crash-ids-file to list crashes from corpus db.
    let list_temp_dir = TempDir::new().expect("Failed to create temporary list directory");
    let crash_ids_file = list_temp_dir.path().join("crash_ids.txt");

    let mut cmd = setup_cargo_fuzztest_command(&sample_crate_path, temp_target_dir.path());
    cmd.arg(test_target)
        .arg("--list-crash-ids")
        .arg("--list-crash-ids-file")
        .arg(&crash_ids_file)
        .arg("--corpus-db")
        .arg(temp_db_dir.path())
        .arg("--centipede-binary-path")
        .arg(&centipede_bin);

    let output = cmd.output().expect("Failed to run cargo-fuzztest in list-crash-ids mode");
    assert!(output.status.success());

    let crash_ids_contents =
        fs::read_to_string(&crash_ids_file).expect("Failed to read crash IDs file");
    let crash_ids: Vec<&str> =
        crash_ids_contents.lines().filter(|line| !line.trim().is_empty()).collect();

    // DISCUSS: We probably should be checking for something more specific, but what would be a
    // good check here?
    expect_true!(!crash_ids.is_empty());
}
