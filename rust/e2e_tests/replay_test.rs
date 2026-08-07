use googletest::matchers;
use googletest::prelude::*;
use std::process::Command;
use test_utils::EnvVars;

#[gtest]
fn replay_by_id_reproduces_panic(fixture: &EnvVars) {
    let test_name = "__fuzztest_mod__find_bug_fuzz_test::find_bug_fuzz_test";
    let normalized_test_name = test_name.replace("::", ".");
    let crash_id = "my_custom_crash_id";

    let target_binary_path = fixture
        .target_binary_path
        .parent()
        .expect("target_binary_path must have a parent")
        .join("replay_fuzz_tests_bin");

    // use a relative path for the target-binary
    let relative_target_binary =
        target_binary_path.strip_prefix("/").unwrap_or(&target_binary_path);

    let db_dir = fixture.tmp_dir_path.join("corpus_db");
    let crash_file_dir =
        db_dir.join(relative_target_binary).join(&normalized_test_name).join("crashing");

    // Write the crashing input to the database
    std::fs::create_dir_all(&crash_file_dir).expect("Failed to create corpus_db directory");
    std::fs::write(crash_file_dir.join(crash_id), &[1, 1])
        .expect("Failed to write crash file to db");

    let process = Command::new(&target_binary_path)
        .arg(test_name)
        .arg("--nocapture")
        .env("FUZZTEST_REPLAY_ID", crash_id)
        .env("FUZZTEST_CORPUS_DB", &db_dir)
        .env("FUZZTEST_CENTIPEDE_BINARY_PATH", &fixture.centipede_path) // Needed for FFI export
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn binary");

    let output = process.wait_with_output().expect("Should terminate");
    let stderr = String::from_utf8_lossy(&output.stderr);

    expect_that!(output.status.success(), eq(false));
    expect_that!(stderr, matchers::contains_substring("panicked at"));
    expect_that!(stderr, matchers::contains_substring("Bug found!"));
    expect_that!(stderr, matchers::contains_substring("FuzzTest controller reported failure"));
}

#[gtest]
fn replay_all_reproduces_all_failures(fixture: &EnvVars) {
    let test_name = "__fuzztest_mod__find_bug_fuzz_test::find_bug_fuzz_test";
    let normalized_test_name = test_name.replace("::", ".");

    let target_binary_path = fixture
        .target_binary_path
        .parent()
        .expect("target_binary_path must have a parent")
        .join("replay_fuzz_tests_bin");

    // use a relative path for the target-binary
    let relative_target_binary =
        target_binary_path.strip_prefix("/").unwrap_or(&target_binary_path);

    let db_dir = fixture.tmp_dir_path.join("corpus_db_all");
    let crash_file_dir =
        db_dir.join(relative_target_binary).join(&normalized_test_name).join("crashing");

    // Write multiple crashing inputs to the database
    std::fs::create_dir_all(&crash_file_dir).expect("Failed to create corpus_db directory");

    // Length 1, [1]
    std::fs::write(crash_file_dir.join("crash_1"), &[1, 1])
        .expect("Failed to write crash_1 file to db");

    // Length 2, [1, 44]
    std::fs::write(crash_file_dir.join("crash_2"), &[2, 1, 44])
        .expect("Failed to write crash_2 file to db");

    // Length 3, [1, 55, 66]
    std::fs::write(crash_file_dir.join("crash_3"), &[3, 1, 55, 66])
        .expect("Failed to write crash_3 file to db");

    let process = std::process::Command::new(&target_binary_path)
        .arg(test_name)
        .env("FUZZTEST_REPLAY_FINDINGS", "true")
        .env("FUZZTEST_CORPUS_DB", &db_dir)
        .env("FUZZTEST_CENTIPEDE_BINARY_PATH", &fixture.centipede_path) // Needed for FFI export
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("Failed to spawn binary");

    let output = process.wait_with_output().expect("Should terminate");
    let stderr = String::from_utf8_lossy(&output.stderr);

    expect_that!(output.status.success(), eq(true));

    // Check that "Bug found!" appears exactly 3 times
    let bug_count = stderr.matches("Bug found!").count();
    expect_that!(bug_count, eq(3));
}
