use googletest::matchers;
use googletest::prelude::*;
use std::process::Command;
use test_utils::EnvVars;

#[gtest]
fn standalone_mode_invokes_centipede(fixture: &EnvVars) {
    let target_binary_path =
        fixture.target_binary_path.parent().unwrap().join("standalone_fuzz_tests_bin");
    let test_name = "__fuzztest_mod__standalone_validation_test::standalone_validation_test";

    let process = Command::new(&target_binary_path)
        .arg(test_name)
        .env("FUZZTEST_FUZZ_FOR", "3s")
        .env("FUZZTEST_PRINT_SUBPROCESS_LOG", "true")
        .env("FUZZTEST_CENTIPEDE_BINARY_PATH", &fixture.centipede_path)
        .env("RUST_TEST_NOCAPTURE", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn binary");

    let output = process.wait_with_output().expect("Should terminate");
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Assert that Centipede actually ran the test binary, and forwarded the worker log.
    // We check for "LOG: STANDALONE_VALIDATION_WORKER_EXECUTED". The prefix "LOG: " indicates that
    // this output is from centipede forwarding the output of the worker (due to --print_runner_log),
    // whereas the rest is from the fuzztest itself.
    expect_that!(
        stderr,
        matchers::contains_substring("LOG: STANDALONE_VALIDATION_WORKER_EXECUTED")
    );
}

#[gtest]
fn standalone_mode_invokes_the_correct_fuzztest(fixture: &EnvVars) {
    let target_binary_path =
        fixture.target_binary_path.parent().unwrap().join("standalone_fuzz_tests_bin");
    let test_name = "__fuzztest_mod__standalone_validation_test::standalone_validation_test";

    let process = Command::new(&target_binary_path)
        .arg(test_name)
        .env("FUZZTEST_FUZZ_FOR", "3s")
        .env("FUZZTEST_PRINT_SUBPROCESS_LOG", "true")
        .env("FUZZTEST_CENTIPEDE_BINARY_PATH", &fixture.centipede_path)
        .env("RUST_TEST_NOCAPTURE", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn binary");

    let output = process.wait_with_output().expect("Should terminate");
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Check that the first test is executed
    expect_that!(
        stderr,
        matchers::contains_substring("LOG: STANDALONE_VALIDATION_WORKER_EXECUTED")
    );

    // Check that the second test does not get executed
    expect_that!(stderr, not(matchers::contains_substring("SECOND_VALIDATION_TEST_EXECUTED")));
}

#[gtest]
fn standalone_mode_handles_worker_crash(fixture: &EnvVars) {
    let test_name = "__fuzztest_mod__find_bug_fuzz_test::find_bug_fuzz_test";

    let process = Command::new(&fixture.target_binary_path)
        .arg(test_name)
        .env("FUZZTEST_FUZZ_FOR", "15s")
        .env("FUZZTEST_PRINT_SUBPROCESS_LOG", "true")
        .env("FUZZTEST_CENTIPEDE_BINARY_PATH", &fixture.centipede_path)
        .env("RUST_TEST_NOCAPTURE", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn binary");

    let output = process.wait_with_output().expect("Should terminate");
    let stderr = String::from_utf8_lossy(&output.stderr);

    expect_that!(stderr, matchers::contains_substring("Property function ran but crashed."));
    expect_that!(stderr, matchers::contains_regex("Signature[ \t]*: Unwinding panic"));
    // Centipede prefixes logs from the crashing worker with "CRASH LOG: ".
    expect_that!(stderr, matchers::contains_substring("CRASH LOG: Bug found!"));
}

#[gtest]
fn standalone_mode_spawns_parallel_jobs(fixture: &EnvVars) {
    let target_binary_path =
        fixture.target_binary_path.parent().unwrap().join("standalone_fuzz_tests_bin");
    let test_name = "__fuzztest_mod__jobs_test::jobs_test";

    let process = Command::new(&target_binary_path)
        .arg(test_name)
        .env("FUZZTEST_FUZZ_FOR", "5s")
        .env("FUZZTEST_JOBS", "4")
        .env("FUZZTEST_PRINT_SUBPROCESS_LOG", "true")
        .env("FUZZTEST_CENTIPEDE_BINARY_PATH", &fixture.centipede_path)
        .env("RUST_TEST_NOCAPTURE", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn binary");

    let output = process.wait_with_output().expect("Should terminate");
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Extract all PIDs from logs.
    // Expected format: "LOG: JOBS_TEST_PID: <pid>"
    use std::collections::HashSet;
    let mut pids = HashSet::new();
    for line in stderr.lines() {
        if let Some(pos) = line.find("LOG: JOBS_TEST_PID: ") {
            let pid_str = &line[pos + "LOG: JOBS_TEST_PID: ".len()..];
            if let Ok(pid) = pid_str.parse::<u32>() {
                pids.insert(pid);
            }
        }
    }

    // We expect 4 different PIDs
    expect_that!(pids.len(), eq(4));
}

#[gtest]
fn standalone_mode_replay_corpus_per_test_budget(fixture: &EnvVars) {
    let target_binary_path =
        fixture.target_binary_path.parent().unwrap().join("standalone_fuzz_tests_bin");

    let corpus_db = fixture.tmp_dir_path.join("corpus_db_per_test");
    let workdir_root = fixture.tmp_dir_path.join("workdir_root_per_test");

    // Centipede appends the binary identifier (relative path) to the corpus database path.
    let identifier = target_binary_path.to_str().unwrap();
    let identifier_relative = identifier.strip_prefix('/').unwrap_or(identifier);

    // Create corpus dirs for tests
    let test1_dir = corpus_db
        .join(identifier_relative)
        .join("__fuzztest_mod__standalone_validation_test.standalone_validation_test")
        .join("coverage");
    let test2_dir = corpus_db
        .join(identifier_relative)
        .join("__fuzztest_mod__second_validation_test.second_validation_test")
        .join("coverage");

    std::fs::create_dir_all(&test1_dir).unwrap();
    std::fs::create_dir_all(&test2_dir).unwrap();

    // Write some corpus inputs.
    // Assuming Arbitrary<i32> consumes 4 bytes.
    use std::fs::File;
    use std::io::Write;

    let mut file1 = File::create(test1_dir.join("input1")).unwrap();
    file1.write_all(&[1, 0, 0, 0]).unwrap();

    let mut file2 = File::create(test1_dir.join("input2")).unwrap();
    file2.write_all(&[2, 0, 0, 0]).unwrap();

    let mut file3 = File::create(test2_dir.join("input3")).unwrap();
    file3.write_all(&[3, 0, 0, 0]).unwrap();

    let process_per_test = Command::new(&target_binary_path)
        .arg("__fuzztest_mod__")
        .env("FUZZTEST_REPLAY_CORPUS_FOR", "3s")
        .env("FUZZTEST_TIME_BUDGET_TYPE", "per-test")
        .env("FUZZTEST_PRINT_SUBPROCESS_LOG", "true")
        .env("FUZZTEST_CENTIPEDE_BINARY_PATH", &fixture.centipede_path)
        .env("FUZZTEST_CORPUS_DB", corpus_db.to_str().unwrap())
        .env("FUZZTEST_WORKDIR_ROOT", workdir_root.to_str().unwrap())
        .env("RUST_TEST_NOCAPTURE", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn binary");

    let output_per_test = process_per_test.wait_with_output().expect("Should terminate");
    let stderr_per_test = String::from_utf8_lossy(&output_per_test.stderr);

    // Verify logs for per-test
    expect_that!(
        stderr_per_test,
        matchers::contains_substring("Replaying __fuzztest_mod__standalone_validation_test.standalone_validation_test for 3s")
    );
    expect_that!(
        stderr_per_test,
        matchers::contains_substring(
            "Replaying __fuzztest_mod__second_validation_test.second_validation_test for 3s"
        )
    );

    // Count executions for per-test
    let mut val1_count = 0;
    let mut val2_count = 0;
    for line in stderr_per_test.lines() {
        if line.contains("STANDALONE_VALIDATION_INPUT:") {
            val1_count += 1;
        }
        if line.contains("SECOND_VALIDATION_INPUT:") {
            val2_count += 1;
        }
    }
    // we had 2 inputs for first test
    expect_that!(val1_count, eq(2));
    // and 1 input for second test
    expect_that!(val2_count, eq(1));
}

#[gtest]
fn standalone_mode_replay_corpus_total_budget(fixture: &EnvVars) {
    let target_binary_path =
        fixture.target_binary_path.parent().unwrap().join("standalone_fuzz_tests_bin");

    let corpus_db = fixture.tmp_dir_path.join("corpus_db_total");
    let workdir_root = fixture.tmp_dir_path.join("workdir_root_total");

    // Centipede appends the binary identifier (relative path) to the corpus database path.
    let identifier = target_binary_path.to_str().unwrap();
    let identifier_relative = identifier.strip_prefix('/').unwrap_or(identifier);

    // Create corpus dirs for tests
    let test1_dir = corpus_db
        .join(identifier_relative)
        .join("__fuzztest_mod__standalone_validation_test.standalone_validation_test")
        .join("coverage");
    let test2_dir = corpus_db
        .join(identifier_relative)
        .join("__fuzztest_mod__second_validation_test.second_validation_test")
        .join("coverage");

    std::fs::create_dir_all(&test1_dir).unwrap();
    std::fs::create_dir_all(&test2_dir).unwrap();

    // Write some corpus inputs.
    // Assuming Arbitrary<i32> consumes 4 bytes.
    use std::fs::File;
    use std::io::Write;

    let mut file1 = File::create(test1_dir.join("input1")).unwrap();
    file1.write_all(&[1, 0, 0, 0]).unwrap();

    let mut file2 = File::create(test1_dir.join("input2")).unwrap();
    file2.write_all(&[2, 0, 0, 0]).unwrap();

    let mut file3 = File::create(test2_dir.join("input3")).unwrap();
    file3.write_all(&[3, 0, 0, 0]).unwrap();

    // We have 3 fuzz tests in the binary. Total 3s / 3 = 1s per test.
    let process_total = Command::new(&target_binary_path)
        .arg("__fuzztest_mod__")
        .env("FUZZTEST_REPLAY_CORPUS_FOR", "3s")
        .env("FUZZTEST_TIME_BUDGET_TYPE", "total")
        .env("FUZZTEST_PRINT_SUBPROCESS_LOG", "true")
        .env("FUZZTEST_CENTIPEDE_BINARY_PATH", &fixture.centipede_path)
        .env("FUZZTEST_CORPUS_DB", corpus_db.to_str().unwrap())
        .env("FUZZTEST_WORKDIR_ROOT", workdir_root.to_str().unwrap())
        .env("RUST_TEST_NOCAPTURE", "1")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn binary");

    let output_total = process_total.wait_with_output().expect("Should terminate");
    let stderr_total = String::from_utf8_lossy(&output_total.stderr);

    // Verify logs for total -> should be 1s
    expect_that!(
        stderr_total,
        matchers::contains_substring("Replaying __fuzztest_mod__standalone_validation_test.standalone_validation_test for 1s")
    );
    expect_that!(
        stderr_total,
        matchers::contains_substring(
            "Replaying __fuzztest_mod__second_validation_test.second_validation_test for 1s"
        )
    );

    // Counts should still match because it finishes early anyway
    let mut val1_count_total = 0;
    let mut val2_count_total = 0;
    for line in stderr_total.lines() {
        if line.contains("STANDALONE_VALIDATION_INPUT:") {
            val1_count_total += 1;
        }
        if line.contains("SECOND_VALIDATION_INPUT:") {
            val2_count_total += 1;
        }
    }
    // we had 2 inputs for first test
    expect_that!(val1_count_total, eq(2));
    // and 1 input for second test
    expect_that!(val2_count_total, eq(1));
}
