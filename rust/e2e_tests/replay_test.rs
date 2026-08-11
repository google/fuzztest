use googletest::matchers;
use googletest::prelude::*;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use test_utils::EnvVars;

fn get_target_binary_path(fixture: &EnvVars) -> PathBuf {
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_replay_fuzz_tests_bin") {
        return PathBuf::from(path);
    }
    fixture
        .target_binary_path
        .parent()
        .expect("target_binary_path must have a parent")
        .join("replay_fuzz_tests_bin")
}

#[gtest]
fn replay_by_id_reproduces_panic(fixture: &EnvVars) {
    let test_name = "__fuzztest_mod__find_two_bugs_fuzz_test::find_two_bugs_fuzz_test";
    let normalized_test_name = test_name.replace("::", ".");

    let target_binary_path = get_target_binary_path(fixture);
    let target_binary_str = target_binary_path.to_str().expect("valid path string");
    let binary_id = target_binary_str.strip_prefix('/').unwrap_or(target_binary_str);

    let db_dir = fixture.tmp_dir_path.join("corpus_db");
    fs::create_dir_all(&db_dir).expect("Failed to create db directory");

    let workdir_root_dir = fixture.tmp_dir_path.join("workdir_root");
    fs::create_dir_all(&workdir_root_dir).expect("Failed to workdir_root directory");

    // 1. Run Centipede to fuzz the target and populate the corpus database.
    Command::new(&target_binary_path)
        .arg(test_name)
        .arg("--exact")
        .env("FUZZTEST_FUZZ_FOR", "60s")
        .env("FUZZTEST_CORPUS_DB", &db_dir)
        .env("FUZZTEST_WORKDIR_ROOT", &workdir_root_dir)
        .env("FUZZTEST_CENTIPEDE_BINARY_PATH", &fixture.centipede_path)
        .env("FUZZTEST_PRINT_SUBPROCESS_LOG", "true")
        .status()
        .expect("Failed to spawn binary");

    // 2. Retrieve the crash IDs from the corpus database using Centipede's --list_crash_ids flag.
    let crash_ids_file = fixture.tmp_dir_path.join("crash_ids.txt");
    let list_args = [
        format!("--binary={}", target_binary_path.display()),
        format!("--fuzztest_binary_identifier={}", binary_id),
        format!("--test_name={}", normalized_test_name),
        format!("--fuzztest_corpus_database={}", db_dir.display()),
        "--list_crash_ids=1".to_string(),
        format!("--list_crash_ids_file={}", crash_ids_file.display()),
    ];
    let list_args_refs: Vec<&str> = list_args.iter().map(|s| s.as_str()).collect();
    test_utils::run_centipede_with_args_expect_termination(fixture, &list_args_refs);

    let crash_ids_contents =
        fs::read_to_string(&crash_ids_file).expect("Failed to read crash IDs file");
    let crash_ids: Vec<&str> =
        crash_ids_contents.lines().filter(|line| !line.trim().is_empty()).collect();

    expect_that!(crash_ids.len(), eq(2));

    // 3. Verify that replaying each crash ID reproduces a panic or segfault.
    let mut reproduced_panic = false;
    let mut reproduced_segfault = false;

    for crash_id in &crash_ids {
        let process = Command::new(&target_binary_path)
            .arg(test_name)
            .arg("--exact")
            .arg("--nocapture")
            .env("FUZZTEST_REPLAY_ID", crash_id)
            .env("FUZZTEST_CORPUS_DB", &db_dir)
            .env("FUZZTEST_CENTIPEDE_BINARY_PATH", &fixture.centipede_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to spawn binary");
        let output = process.wait_with_output().expect("Should terminate");
        let stderr = String::from_utf8_lossy(&output.stderr);

        expect_that!(output.status.success(), eq(false));
        expect_that!(stderr, matchers::contains_substring("FuzzTest controller reported failure"));

        if stderr.contains("Bug 1 found!") {
            reproduced_panic = true;
        } else if stderr.contains("Bug 2 found!") {
            reproduced_segfault = true;
        }
    }

    expect_that!(reproduced_panic, eq(true));
    expect_that!(reproduced_segfault, eq(true));
}

#[gtest]
fn replay_all_reproduces_all_failures(fixture: &EnvVars) {
    let test_name = "__fuzztest_mod__find_two_bugs_fuzz_test::find_two_bugs_fuzz_test";

    let target_binary_path = get_target_binary_path(fixture);
    let target_binary_str = target_binary_path.to_str().expect("valid path string");
    let binary_id = target_binary_str.strip_prefix('/').unwrap_or(target_binary_str);

    let db_dir = fixture.tmp_dir_path.join("corpus_db_all");
    fs::create_dir_all(&db_dir).expect("Failed to create db directory");

    let workdir_root_dir = fixture.tmp_dir_path.join("workdir_root_all");
    fs::create_dir_all(&workdir_root_dir).expect("Failed to workdir_root_all directory");

    // 1. Run Centipede to fuzz the target and populate the corpus database.
    Command::new(&target_binary_path)
        .arg(test_name)
        .arg("--exact")
        .env("FUZZTEST_FUZZ_FOR", "60s")
        .env("FUZZTEST_CORPUS_DB", &db_dir)
        .env("FUZZTEST_WORKDIR_ROOT", &workdir_root_dir)
        .env("FUZZTEST_CENTIPEDE_BINARY_PATH", &fixture.centipede_path)
        .env("FUZZTEST_PRINT_SUBPROCESS_LOG", "true")
        .status()
        .expect("Failed to spawn binary");

    // 2. Replay all findings using FUZZTEST_REPLAY_FINDINGS=true.
    let process = Command::new(&target_binary_path)
        .arg(test_name)
        .arg("--exact")
        .env("FUZZTEST_REPLAY_FINDINGS", "true")
        .env("FUZZTEST_CORPUS_DB", &db_dir)
        .env("FUZZTEST_CENTIPEDE_BINARY_PATH", &fixture.centipede_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to spawn binary");

    let output = process.wait_with_output().expect("Should terminate");
    let stderr = String::from_utf8_lossy(&output.stderr);

    expect_that!(output.status.success(), eq(true));
    expect_that!(stderr, matchers::contains_substring("Bug 1 found!"));
    expect_that!(stderr, matchers::contains_substring("Bug 2 found!"));
}
