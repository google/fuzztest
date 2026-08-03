#![feature(cfg_sanitize)]

#[cfg(any(sanitize = "address", sanitize = "memory"))]
use googletest::matchers;
#[cfg(any(sanitize = "address", sanitize = "memory"))]
use googletest::prelude::*;
#[cfg(any(sanitize = "address", sanitize = "memory"))]
use std::fs;
#[cfg(any(sanitize = "address", sanitize = "memory"))]
use test_utils::EnvVars;

#[gtest]
#[cfg(sanitize = "address")]
fn ensure_use_after_free_signature_with_asan(fixture: &EnvVars) {
    let work_dir = fixture.tmp_dir_path.join("WD"); // For permissions
    fs::create_dir_all(&work_dir).expect("Failed to create working directory");

    let args = [
        &format!("--binary={}", fixture.target_binary_path.display()),
        &format!("--workdir={}", work_dir.display()),
        "--exit_on_crash",
        "--test_name=__fuzztest_mod__use_after_free_asan_death_test.use_after_free_asan_death_test",
    ];

    let stderr = test_utils::run_centipede_with_args_expect_termination(fixture, &args);

    expect_that!(stderr, matchers::contains_regex("Signature[ \t]*: heap-use-after-free"));
}

// TODO(yamilmorales): Enable this test on presubmit with --config=msan.
#[gtest]
#[cfg(sanitize = "memory")]
fn ensure_sanitizer_crash_signature_with_msan(fixture: &EnvVars) {
    let work_dir = fixture.tmp_dir_path.join("WD"); // For permissions
    fs::create_dir_all(&work_dir).expect("Failed to create working directory");

    let args = [
        &format!("--binary={}", fixture.target_binary_path.display()),
        &format!("--workdir={}", work_dir.display()),
        "--exit_on_crash",
        "--test_name=__fuzztest_mod__msan_death_test.msan_death_test",
        "--use_cmp_features=0", // Prevent msan from detecting nested bugs and aborting without
                                // triggering the death callback.
    ];

    let stderr = test_utils::run_centipede_with_args_expect_termination(fixture, &args);

    expect_that!(stderr, matchers::contains_regex("Signature[ \t]*: Sanitizer crash"));
}
