use googletest::matchers;
use googletest::prelude::*;
use std::fs;
use std::process::Command;
use test_utils::EnvVars;

#[gtest]
fn get_binary_id_test(fixture: &EnvVars) {
    let binary_id_file = fixture.tmp_dir_path.join("binary_id.txt");

    let mut process = Command::new(&fixture.target_binary_path)
        .env(
            "CENTIPEDE_RUNNER_FLAGS",
            format!(":dump_binary_id:binary_id_output={}:", binary_id_file.display()),
        )
        .spawn()
        .expect("Failed to spawn binary");

    process.wait().expect("Should terminate");
    expect_that!(
        fs::read_to_string(binary_id_file).unwrap(),
        matchers::contains_substring(
            (fixture.target_binary_path.file_name()).unwrap().to_string_lossy()
        )
    );
}
