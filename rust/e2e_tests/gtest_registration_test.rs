use googletest::matchers;
use googletest::prelude::*;
use std::env;
use std::path::PathBuf;
use std::process::Command;

#[gtest]
fn test_fuzztests_are_registered_as_gtests() {
    let src_dir_path = PathBuf::from(env::var("TEST_SRCDIR").unwrap());
    let target_binary_path = src_dir_path
        .join("_main/rust/e2e_tests/testdata/fuzz_tests_as_gtests");

    // Run the test binary with `--list` to list all registered tests.
    let output = Command::new(&target_binary_path)
        .arg("--list")
        .output()
        .expect("Failed to execute test binary");

    assert!(output.status.success(), "Test binary failed to execute with --list");

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Verify that the expected fuzz tests are listed as regular tests.
    expect_that!(stdout, matchers::contains_substring("bool_fuzz_test: test"));
    expect_that!(stdout, matchers::contains_substring("multi_arg_fuzz_test: test"));
}

#[gtest]
fn test_fuzztest_property_function_executes_in_gtest() {
    let src_dir_path = PathBuf::from(env::var("TEST_SRCDIR").unwrap());
    let target_binary_path = src_dir_path
        .join("_main/rust/e2e_tests/testdata/fuzz_tests_as_gtests");

    // Run a fuzz test
    let output = Command::new(&target_binary_path)
        .arg("bool_fuzz_test")
        .arg("--nocapture")
        .output()
        .expect("Failed to execute test binary");

    assert!(output.status.success(), "Test binary failed to execute `bool_fuzz_test`");

    let stdout = String::from_utf8_lossy(&output.stdout);

    expect_that!(stdout, matchers::contains_substring("bool_fuzz_test property function ran..."));
}
