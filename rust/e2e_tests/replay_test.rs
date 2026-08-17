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

    let target_binary_path = get_target_binary_path(fixture);

    let db_dir = fixture.tmp_dir_path.join("replay_by_id_reproduces_panic").join("corpus_db");
    fs::create_dir_all(&db_dir).expect("Failed to create db directory");

    let workdir_root_dir =
        fixture.tmp_dir_path.join("replay_by_id_reproduces_panic").join("workdir_root");
    fs::create_dir_all(&workdir_root_dir).expect("Failed to workdir_root directory");

    // 1. Run Centipede to fuzz the target and populate the corpus database.
    Command::new(&target_binary_path)
        .arg(test_name)
        .arg("--exact")
        .env("FUZZTEST_FUZZ_FOR", "15s")
        .env("FUZZTEST_CORPUS_DB", &db_dir)
        .env("FUZZTEST_WORKDIR_ROOT", &workdir_root_dir)
        .env("FUZZTEST_CENTIPEDE_BINARY_PATH", &fixture.centipede_path)
        .status()
        .expect("Failed to spawn binary");

    // 2. Retrieve the crash IDs from the corpus database using FUZZTEST_LIST_CRASH_IDS.
    let crash_ids_file =
        fixture.tmp_dir_path.join("replay_by_id_reproduces_panic").join("crash_ids.txt");
    let status = Command::new(&target_binary_path)
        .arg(test_name)
        .arg("--exact")
        .env("FUZZTEST_LIST_CRASH_IDS", "true")
        .env("FUZZTEST_LIST_CRASH_IDS_FILE", &crash_ids_file)
        .env("FUZZTEST_CORPUS_DB", &db_dir)
        .env("FUZZTEST_CENTIPEDE_BINARY_PATH", &fixture.centipede_path)
        .status()
        .expect("Failed to execute target binary to list crash IDs");
    expect_true!(status.success());

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

    let db_dir =
        fixture.tmp_dir_path.join("replay_all_reproduces_all_failures").join("corpus_db_all");
    fs::create_dir_all(&db_dir).expect("Failed to create db directory");

    let workdir_root_dir =
        fixture.tmp_dir_path.join("replay_all_reproduces_all_failures").join("workdir_root_all");
    fs::create_dir_all(&workdir_root_dir).expect("Failed to workdir_root_all directory");

    // 1. Run Centipede to fuzz the target and populate the corpus database.
    Command::new(&target_binary_path)
        .arg(test_name)
        .arg("--exact")
        .env("FUZZTEST_FUZZ_FOR", "15s")
        .env("FUZZTEST_CORPUS_DB", &db_dir)
        .env("FUZZTEST_WORKDIR_ROOT", &workdir_root_dir)
        .env("FUZZTEST_CENTIPEDE_BINARY_PATH", &fixture.centipede_path)
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
