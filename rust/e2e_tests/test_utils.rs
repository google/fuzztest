use googletest::fixtures::Fixture;
use std::env;
use std::path::PathBuf;
use std::process::Command;

pub struct EnvVars {
    pub tmp_dir_path: PathBuf,
    pub target_binary_path: PathBuf,
    pub centipede_path: PathBuf,
}

impl Fixture for EnvVars {
    fn set_up() -> googletest::Result<Self> {
        const TARGET_BINARY: &str =
            "com_google_fuzztest/rust/e2e_tests/testdata/fuzztest_main";
        const CENTIPEDE: &str =
            "com_google_fuzztest/centipede/google/centipede_uninstrumented";
        let src_dir_path = PathBuf::from(env::var("TEST_SRCDIR").unwrap());
        let tmp_dir_path = PathBuf::from(env::var("TEST_TMPDIR").unwrap());
        let target_binary_path = src_dir_path.join(PathBuf::from(TARGET_BINARY));
        let centipede_path = src_dir_path.join(PathBuf::from(CENTIPEDE));

        Ok(EnvVars { tmp_dir_path, target_binary_path, centipede_path })
    }
    fn tear_down(self) -> googletest::Result<()> {
        Ok(())
    }
}

/// Returns stderr of a Centipede process with `args` that is expected to terminate through some
/// internal flag. e.g. `--exit_on_crash` or `--stop_after`.
///
/// Each arg of `args` should be a string that Centipede recognizes containing a flag with a
/// possible value, e.g. `--test_name=my_test_name` or `--exit_on_crash`. In addition to `args`,
/// the function will also pass `--populate_binary_info=0`, `--fork_server=0`,
/// `--persistent_mode=0`, and `--env_diff_for_binaries`.
pub fn run_centipede_with_args_expect_termination(fixture: &EnvVars, args: &[&str]) -> String {
    // Disable interference from Bazel environment variables.
    let env_diff = [
        "-TEST_DIAGNOSTICS_OUTPUT_DIR",
        "-TEST_INFRASTRUCTURE_FAILURE_FILE",
        "-TEST_LOGSPLITTER_OUTPUT_FILE",
        "-TEST_PREMATURE_EXIT_FILE",
        "-TEST_RANDOM_SEED",
        "-TEST_RUN_NUMBER",
        "-TEST_SHARD_INDEX",
        "-TEST_SHARD_STATUS_FILE",
        "-TEST_TOTAL_SHARDS",
        "-TEST_UNDECLARED_OUTPUTS_ANNOTATIONS_DIR",
        "-TEST_UNDECLARED_OUTPUTS_DIR",
        "-TEST_WARNINGS_OUTPUT_FILE",
        "-GTEST_OUTPUT",
        "-XML_OUTPUT_FILE",
    ];
    let process = Command::new(&fixture.centipede_path)
        .arg("--populate_binary_info=0")
        .arg("--fork_server=0")
        .arg("--persistent_mode=0")
        .arg(format!("--env_diff_for_binaries={}", env_diff.join(",")))
        .args(args)
        .output()
        .expect("Centipede should have executed");

    String::from_utf8_lossy(&process.stderr).to_string()
}
