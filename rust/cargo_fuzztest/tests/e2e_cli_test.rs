use googletest::prelude::*;
use std::env;
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

fn get_dummy_crate_path(dummy_crate_name: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dummy_crate_path = Path::new(manifest_dir).join(format!("test_crates/{dummy_crate_name}"));
    assert!(dummy_crate_path.exists());
    dummy_crate_path
}

#[gtest]
fn test_cargo_fuzztest_e2e_smoke_test() {
    // Resolve the absolute path of the dummy crate
    let dummy_crate_path = get_dummy_crate_path("dummy_fuzz_crate");

    // Create a temporary directory for Cargo build outputs
    let temp_target_dir = TempDir::new().expect("Failed to create temporary target directory");

    // Invoke: `cargo fuzztest` inside the resolved dummy crate directory.
    let output = setup_cargo_fuzztest_command(&dummy_crate_path, temp_target_dir.path())
        .output()
        .expect("Failed to run cargo-fuzztest command");

    // Verify that both fuzztest targets in the crate were run in smoke-test mode
    let stdout_str = String::from_utf8_lossy(&output.stdout);
    expect_true!(stdout_str.contains("dummy_fuzztest_target"));
    expect_true!(stdout_str.contains("another_dummy_fuzztest_target"));
}

#[gtest]
fn test_cargo_fuzztest_e2e_list() {
    // Resolve the absolute path of the dummy crate
    let dummy_crate_path = get_dummy_crate_path("dummy_fuzz_crate");

    let temp_target_dir = TempDir::new().expect("Failed to create temporary target directory");

    // Invoke: `cargo-fuzztest --list` inside the dummy crate directory
    let output = setup_cargo_fuzztest_command(&dummy_crate_path, temp_target_dir.path())
        .arg("--list")
        .output()
        .expect("Failed to run cargo-fuzztest --list command");

    // Verify execution completed successfully
    expect_true!(output.status.success());

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    expect_true!(stdout_str.contains("dummy_fuzztest_target"));
    expect_true!(stdout_str.contains("another_dummy_fuzztest_target"));
}

#[gtest]
fn test_cargo_fuzztest_e2e_specific_target() {
    // Resolve the absolute path of the dummy crate
    let dummy_crate_path = get_dummy_crate_path("dummy_fuzz_crate");

    let temp_target_dir = TempDir::new().expect("Failed to create temporary target directory");

    let mut cmd = setup_cargo_fuzztest_command(&dummy_crate_path, temp_target_dir.path());

    let centipede_bin = env::var("CENTIPEDE_BINARY_PATH")
        .expect("CENTIPEDE_BINARY_PATH needs to be set for the test");

    cmd.arg("__fuzztest_mod__dummy_fuzztest_target::dummy_fuzztest_target")
        .arg("--fuzz-for=2s")
        .env_remove("CENTIPEDE_BINARY_PATH")
        .arg("--centipede-binary-path")
        .arg(centipede_bin);

    let output = cmd.output().expect("Failed to run cargo-fuzztest command");

    let stdout_str = String::from_utf8_lossy(&output.stdout);
    expect_true!(stdout_str.contains("dummy_fuzztest_target"));
    expect_false!(stdout_str.contains("another_dummy_fuzztest_target"));
}

#[gtest]
fn test_cargo_fuzztest_e2e_parallel_jobs() {
    let cargo_fuzztest_bin = env!("CARGO_BIN_EXE_cargo-fuzztest");
    assert!(Path::new(cargo_fuzztest_bin).exists());

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let dummy_crate_path = Path::new(manifest_dir).join("test_crates/dummy_fuzz_crate");
    assert!(dummy_crate_path.exists());

    let temp_target_dir = TempDir::new()
        .expect("creating a temporary directory on standard temp filesystem cannot fail");

    let centipede_bin_opt = env::var("CENTIPEDE_BINARY_PATH").ok();

    let mut cmd = Command::new(cargo_fuzztest_bin);
    cmd.current_dir(&dummy_crate_path)
        .arg("__fuzztest_mod__jobs_fuzztest_target::jobs_fuzztest_target")
        .arg("--jobs")
        .arg("4")
        .arg("--fuzz-for")
        .arg("5s")
        .env("CARGO_TARGET_DIR", temp_target_dir.path())
        .env("FUZZTEST_PRINT_SUBPROCESS_LOG", "true");

    // Remove inherited environment variable and pass centipede binary path explicitly via CLI argument.
    if let Some(ref centipede_bin) = centipede_bin_opt {
        cmd.env_remove("CENTIPEDE_BINARY_PATH").arg("--centipede-binary-path").arg(centipede_bin);
    }

    let output = cmd.output().expect("running local cargo-fuzztest sub-process should complete");

    if !output.status.success() {
        eprintln!("\n=================== cargo-fuzztest STDOUT ===================");
        eprintln!("{}", String::from_utf8_lossy(&output.stdout));
        eprintln!("=============================================================");

        eprintln!("\n=================== cargo-fuzztest STDERR ===================");
        eprintln!("{}", String::from_utf8_lossy(&output.stderr));
        eprintln!("=============================================================\n");
    }

    expect_true!(output.status.success());

    // When Centipede path was passed via CLI argument, verify that 4 parallel worker
    // processes were spawned with distinct PIDs.
    if centipede_bin_opt.is_some() {
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
}
