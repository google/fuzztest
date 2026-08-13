// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use googletest::matchers;
use googletest::prelude::*;
use rand::RngExt;
use std::fs;
use test_utils::EnvVars;

fn run_centipede_test<'a>(
    fixture: &EnvVars,
    test_name: &str,
    extra_args: impl IntoIterator<Item = &'a str>,
) -> String {
    let random_suffix: String =
        rand::rng().sample_iter(&rand::distr::Alphanumeric).take(10).map(char::from).collect();
    let work_dir_name = format!("WD_{}_{}", test_name, random_suffix);
    let work_dir = fixture.tmp_dir_path.join(work_dir_name);
    fs::create_dir_all(&work_dir).expect("Failed to create working directory");

    let rust_test_name = test_name.replace(".", "::");
    let mut args: Vec<String> = vec![
        format!(
            "--binary={} --nocapture {} --exact",
            fixture.target_binary_path.display(),
            rust_test_name
        ),
        format!("--workdir={}", work_dir.display()),
        format!("--test_name={}", test_name),
    ];
    args.extend(extra_args.into_iter().map(|s| s.to_string()));

    let args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    test_utils::run_centipede_with_args_expect_termination(fixture, &args)
}

#[gtest]
fn find_bug_with_centipede_test(fixture: &EnvVars) {
    let stderr = run_centipede_test(
        fixture,
        "__fuzztest_mod__find_bug_fuzz_test.find_bug_fuzz_test",
        ["--exit_on_crash"],
    );

    expect_that!(stderr, matchers::contains_substring("Property function ran but crashed."));
    expect_that!(stderr, matchers::contains_regex("Signature[ \t]*: Unwinding panic"));
    expect_that!(stderr, matchers::contains_substring("CRASH LOG: Bug found!"));
}

#[gtest]
fn ensure_custom_mutator_with_centipede_test(fixture: &EnvVars) {
    let stderr = run_centipede_test(
        fixture,
        "__fuzztest_mod__find_bug_fuzz_test.find_bug_fuzz_test",
        ["--stop_after=10s"],
    );

    // In the 10 seconds that Centipede ran, the fuzzing loop should have requested to mutate.
    expect_that!(stderr, matchers::contains_substring("Custom mutator detected"));
}

#[gtest]
fn ensure_seed_emition_with_centipede_test(fixture: &EnvVars) {
    let stderr = run_centipede_test(
        fixture,
        "__fuzztest_mod__find_bug_fuzz_test.find_bug_fuzz_test",
        ["--exit_on_crash", "--require_seeds"],
    );

    // If not present, then exited early because no seeds were emitted.
    expect_that!(stderr, matchers::contains_substring("Number of input seeds available"));
}

#[gtest]
fn ensure_features_work_finding_rarer_bug(fixture: &EnvVars) {
    let stderr = run_centipede_test(
        fixture,
        "__fuzztest_mod__find_rarer_bug_fuzz_test.find_rarer_bug_fuzz_test",
        ["--exit_on_crash"],
    );

    // Centipede's passes a length-prefixed screen, so the initial \\\\x5 stands for
    // that length, not any kind of hex-escaping.
    expect_that!(stderr, matchers::contains_regex("Input bytes[ \t]*: \\\\x5PaNiC"));
    expect_that!(stderr, matchers::contains_substring("CRASH LOG: Bug found!"));
}

#[gtest]
fn ensure_features_work_finding_rarer_bug_2_args(fixture: &EnvVars) {
    let stderr = run_centipede_test(
        fixture,
        "__fuzztest_mod__find_rarer_bug_2_args_fuzz_test.find_rarer_bug_2_args_fuzz_test",
        ["--exit_on_crash"],
    );

    expect_that!(stderr, matchers::contains_substring("CRASH LOG: Bug found!"));
}

#[gtest]
fn ensure_features_work_finding_rarer_bug_3_args(fixture: &EnvVars) {
    let stderr = run_centipede_test(
        fixture,
        "__fuzztest_mod__find_rarer_bug_3_args_fuzz_test.find_rarer_bug_3_args_fuzz_test",
        ["--exit_on_crash"],
    );

    expect_that!(stderr, matchers::contains_substring("CRASH LOG: Bug found!"));
}

#[gtest]
fn ensure_emit_error_with_centipede_test(fixture: &EnvVars) {
    let stderr = run_centipede_test(
        fixture,
        "__fuzztest_mod__fallible_fuzz_test.fallible_fuzz_test",
        ["--stop_after=5s"],
    );

    expect_that!(
        stderr,
        matchers::contains_substring(
            "Emitted failure output: Failed to mutate: Intentional mutate failure"
        )
    );
}
