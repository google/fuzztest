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
