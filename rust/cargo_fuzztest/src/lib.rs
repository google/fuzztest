use anyhow::{Context, Result};
use clap::Parser;
pub use fuzztest_options::{
    ExecutionMode, FuzzFor, FuzzOptions, FuzzTestOptions, ReplayCrashOptions,
};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser, Debug, Clone, Default)]
pub struct CargoFuzzTestOptions {
    #[command(flatten)]
    pub fuzztest_options: FuzzTestOptions,

    /// List all fuzz tests in the crate without running them.
    #[arg(long)]
    pub list: bool,

    /// Optional test target name to run (for example, `__fuzztest_mod__my_test::my_test`).
    ///
    /// If omitted, all generated fuzz tests in the binary are run.
    #[arg()]
    pub test_path: Option<String>,

    /// Optional path to the Centipede binary executable.
    ///
    /// When specified via CLI `--centipede-binary-path <path>`, this is forwarded to
    /// the compiled test executable via the `FUZZTEST_CENTIPEDE_BINARY_PATH` environment variable.
    #[arg(long)]
    pub centipede_binary_path: Option<String>,
}

impl CargoFuzzTestOptions {
    fn check_centipede_binary_path_is_set(&self) -> Result<()> {
        if self.centipede_binary_path.is_none() {
            anyhow::bail!("`--centipede-binary-path` needs to be specified");
        }
        Ok(())
    }

    fn check_corpus_db_is_set(&self) -> Result<()> {
        if self.fuzztest_options.corpus_db.is_none() {
            anyhow::bail!("`--corpus-db` needs to be specified");
        }
        Ok(())
    }

    /// Returns the `ExecutionMode` derived from CLI options.
    pub fn execution_mode(&self) -> Result<ExecutionMode> {
        if self.list {
            return Ok(ExecutionMode::ListFuzzTests);
        }

        let mode = ExecutionMode::from_fuzztest_options(&self.fuzztest_options);

        // TODO(the-shank): improve this
        if self.test_path.is_some() && mode == ExecutionMode::SmokeTest {
            // infinite fuzzing
            self.check_centipede_binary_path_is_set()?;
            return Ok(ExecutionMode::Fuzz(FuzzOptions {
                fuzz_for: self.fuzztest_options.fuzz_for.unwrap_or(FuzzFor::Indefinitely),
                jobs: self.fuzztest_options.jobs,
            }));
        }

        let mode = match &mode {
            ExecutionMode::Fuzz(_) => {
                self.check_centipede_binary_path_is_set()?;
                mode
            }
            ExecutionMode::ReplayCrash(_) => {
                self.check_centipede_binary_path_is_set()?;
                self.check_corpus_db_is_set()?;
                mode
            }
            ExecutionMode::SmokeTest => mode,
            _ => {
                anyhow::bail!("mode not yet supported");
            }
        };

        Ok(mode)
    }

    /// Returns the test filter pattern and whether exact matching should be enabled.
    ///
    /// If `test_path` is set, returns `(target, true)` for exact test execution.
    /// Otherwise, returns `("__fuzztest_mod__", false)` to run all fuzz tests.
    pub fn test_filter(&self) -> (&str, bool) {
        match &self.test_path {
            Some(test_path) => (test_path.as_str(), true),
            None => ("__fuzztest_mod__", false),
        }
    }
}

/// Queries Cargo via `cargo -vV` to discover the default host target triple (e.g. `x86_64-unknown-linux-gnu`).
pub fn get_host_target_triple() -> anyhow::Result<String> {
    let cargo_bin = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let output = std::process::Command::new(&cargo_bin)
        .arg("-vV")
        .output()
        .context("while attempting to run `cargo -vV` to determine host target triple")?;

    if !output.status.success() {
        anyhow::bail!("cargo -vV exited with status: {:?}", output.status);
    }

    let stdout_str = String::from_utf8(output.stdout)
        .context("while attempting to parse stdout of cargo -vV as UTF-8")?;
    parse_host_triple(&stdout_str)
}

/// Parses the output of `cargo -vV` to extract the host target triple.
///
/// Cargo's verbose version output contains lines of key-value metadata, including
/// a `host: <triple>` line representing the host build architecture.
fn parse_host_triple(stdout: &str) -> anyhow::Result<String> {
    for line in stdout.lines() {
        if let Some(triple) = line.strip_prefix("host: ") {
            return Ok(triple.trim().to_string());
        }
    }
    anyhow::bail!("Failed to find 'host: ' line in cargo -vV output")
}

/// Parses CLI options for the `cargo-fuzztest` binary.
///
/// When invoked via `cargo fuzztest ...`, Cargo passes `"fuzztest"` as `argv[1]`.
/// We strip `"fuzztest"` if present so `clap` can parse options cleanly.
pub fn parse_cli_options() -> CargoFuzzTestOptions {
    let mut args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.len() > 1 && args[1] == "fuzztest" {
        args.remove(1);
    }
    CargoFuzzTestOptions::parse_from(args)
}

pub struct FuzztestRunner {
    pub host_triple: String,
    pub options: CargoFuzzTestOptions,
}

impl FuzztestRunner {
    pub fn new(host_triple: String, options: CargoFuzzTestOptions) -> Self {
        Self { host_triple, options }
    }

    /// Constructs `cargo test --no-run --message-format=json --target <host_triple> --lib`.
    pub fn build_compile_command(&self) -> Command {
        let mut cmd = Command::new("cargo");
        cmd.args([
            "test",
            "--no-run",
            "--message-format=json",
            "--target",
            &self.host_triple,
            "--lib",
        ]);

        // We set the target-specific rustflags (`CARGO_TARGET_<TRIPLE>_RUSTFLAGS`) instead of a global
        // `RUSTFLAGS` environment variable.
        //
        // If a global `RUSTFLAGS` is set, Cargo applies sanitizer coverage flags to both target code
        // and host tools (such as build scripts and proc-macros). This causes host tool compilation
        // to fail during linking because host tools are not linked against the fuzzer runtime
        // (which implements the sanitizer coverage callbacks).
        //
        // Using a target-specific key combined with Cargo's explicit `--target` flag ensures
        // that host tool helper crates are compiled normally, while only our target fuzz tests
        // receive fuzzer instrumentation.
        let target_env_key =
            format!("CARGO_TARGET_{}_RUSTFLAGS", self.host_triple.replace('-', "_").to_uppercase());
        let outer_rustflags = std::env::var("RUSTFLAGS").ok();
        let outer_target_rustflags = std::env::var(&target_env_key).ok();
        let mut rustflags_value = match (outer_rustflags, outer_target_rustflags) {
            (Some(rf), Some(trf)) => format!("{rf} {trf}"),
            (Some(rf), None) => rf,
            (None, Some(trf)) => trf,
            (None, None) => String::new(),
        };
        if !rustflags_value.is_empty() {
            rustflags_value.push(' ');
        }
        rustflags_value.push_str(
            "-Cpasses=sancov-module \
                                       -Cllvm-args=-sanitizer-coverage-level=4 \
                                       -Cllvm-args=-sanitizer-coverage-trace-pc-guard \
                                       -Cllvm-args=-sanitizer-coverage-pc-table \
                                       -Cllvm-args=-sanitizer-coverage-trace-compares",
        );
        cmd.env(target_env_key, rustflags_value);

        cmd
    }

    /// Parses the JSON stream emitted by `cargo test --message-format=json` to extract the compiled test executable.
    pub fn parse_compiler_messages(json_output: &str) -> Result<PathBuf> {
        let mut executables = Vec::new();

        for line in json_output.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(trimmed) {
                let is_compiler_artifact =
                    val.get("reason").and_then(|r| r.as_str()) == Some("compiler-artifact");
                let is_test_profile =
                    val.get("profile").and_then(|p| p.get("test")).and_then(|t| t.as_bool())
                        == Some(true);

                if is_compiler_artifact && is_test_profile {
                    if let Some(exe) = val.get("executable").and_then(|e| e.as_str()) {
                        executables.push(PathBuf::from(exe));
                    }
                }
            }
        }

        match executables.len() {
            1 => Ok(executables.remove(0)),
            0 => anyhow::bail!("no test executable found in Cargo compiler JSON output"),
            // TODO(the-shank): support multiple test executables, for example from --lib and
            // --bins targets.
            _ => anyhow::bail!(
                "multiple test executables found in Cargo compiler output: {:?}. Expected exactly one.",
                executables
            ),
        }
    }

    /// Construct the direct binary invocation command.
    pub fn build_run_command(&self, test_binary: &Path) -> Result<Command> {
        let mut cmd = Command::new(test_binary);

        match self.options.test_filter() {
            (test_path, true) => {
                cmd.arg(test_path);
                cmd.arg("--exact");
            }
            ("__fuzztest_mod__", false) => {
                cmd.arg("__fuzztest_mod__");
            }
            _ => {
                unreachable!("no other combination is possible")
            }
        }

        let mode = self.options.execution_mode()?;
        match mode {
            ExecutionMode::ListFuzzTests => {
                cmd.arg("--list");
            }

            ExecutionMode::Fuzz(fuzz_options) => {
                let FuzzOptions { fuzz_for, jobs } = fuzz_options;
                match fuzz_for {
                    FuzzFor::Indefinitely => {
                        cmd.env("FUZZTEST_FUZZ_FOR", "inf");
                    }
                    FuzzFor::Duration(duration) => {
                        cmd.env("FUZZTEST_FUZZ_FOR", duration.to_string());
                    }
                }
                if let Some(jobs) = jobs {
                    cmd.env("FUZZTEST_JOBS", jobs.to_string());
                }
            }

            ExecutionMode::ReplayCrash(replay_options) => {
                cmd.env("FUZZTEST_REPLAY_ID", replay_options.replay_id);
            }

            ExecutionMode::SmokeTest => {
                // nothing to be done
            }
            _ => {
                // TODO(the-shank): add support for other modes.
            }
        }

        if let Some(corpus_db) = &self.options.fuzztest_options.corpus_db {
            cmd.env("FUZZTEST_CORPUS_DB", corpus_db);
        }

        if let Some(workdir_root) = &self.options.fuzztest_options.workdir_root {
            cmd.env("FUZZTEST_WORKDIR_ROOT", workdir_root);
        }

        // If `--centipede-binary-path` was passed to `cargo-fuzztest`, forward it to the
        // child test executable via `FUZZTEST_CENTIPEDE_BINARY_PATH` environment variable so the
        // fuzzer runtime can locate and run Centipede during continuous fuzzing.
        if let Some(centipede_binary_path) = &self.options.centipede_binary_path {
            cmd.env("FUZZTEST_CENTIPEDE_BINARY_PATH", centipede_binary_path);
        }

        if self.options.fuzztest_options.print_subprocess_log {
            cmd.env("FUZZTEST_PRINT_SUBPROCESS_LOG", "true");
            cmd.arg("--nocapture");
        }

        Ok(cmd)
    }

    /// Runs the tool in two steps:
    /// 1. build the test binary
    /// 2. execute the target mode command on the compiled test binary
    pub fn run(&self) -> Result<i32> {
        // 1. build the test binary
        let compile_output = self
            .build_compile_command()
            .output()
            .context("while attempting to execute `cargo test --no-run` compilation command")?;

        if !compile_output.status.success() {
            // print compiler's stderr to help the user diagnose compilation errors.
            eprintln!("{}", String::from_utf8_lossy(&compile_output.stdout));
            eprintln!("{}", String::from_utf8_lossy(&compile_output.stderr));
            anyhow::bail!(
                "cargo compilation failed with exit code: {:?}",
                compile_output.status.code()
            );
        }

        let json_stdout = String::from_utf8(compile_output.stdout)
            .context("while attempting to parse compilation JSON output as UTF-8")?;
        let test_binary = Self::parse_compiler_messages(&json_stdout)?;

        // 2. run the test binary
        let mut run_cmd = self
            .build_run_command(&test_binary)
            .context("while attempting to construct test binary run command")?;
        let status =
            run_cmd.status().context("while attempting to execute compiled test binary")?;

        Ok(status.code().unwrap_or(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;

    #[gtest]
    fn test_parse_host_triple_valid() {
        let stdout = "rustc 1.75.0 (82e5872f3 2023-12-21)\n\
                      binary: rustc\n\
                      commit-hash: 82e5872f3d693c9d7d4c2c56a8fb7f59d47c4058\n\
                      commit-date: 2023-12-21\n\
                      host: x86_64-unknown-linux-gnu\n\
                      release: 1.75.0\n\
                      LLVM version: 17.0.6\n";
        let result = parse_host_triple(stdout).expect("valid stdout parsing should succeed");
        assert_eq!(result, "x86_64-unknown-linux-gnu");
    }

    #[gtest]
    fn test_parse_host_triple_missing_host() {
        let stdout = "rustc 1.75.0 (82e5872f3 2023-12-21)\n\
                      binary: rustc\n";
        let result = parse_host_triple(stdout);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to find 'host: '"));
    }

    #[gtest]
    fn test_build_run_command_default() {
        let options = CargoFuzzTestOptions::default();
        let runner = FuzztestRunner::new("x86_64-unknown-linux-gnu".to_string(), options);
        let cmd =
            runner.build_run_command(Path::new("/tmp/test_bin")).expect("should build run command");
        let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().to_string()).collect();
        assert_eq!(args, vec!["__fuzztest_mod__"]);
    }

    #[gtest]
    fn test_build_run_command_list() {
        let options = CargoFuzzTestOptions { list: true, ..Default::default() };
        let runner = FuzztestRunner::new("x86_64-unknown-linux-gnu".to_string(), options);
        let cmd =
            runner.build_run_command(Path::new("/tmp/test_bin")).expect("should build run command");
        let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().to_string()).collect();
        assert_eq!(args, vec!["__fuzztest_mod__", "--list"]);
    }

    #[gtest]
    fn test_execution_mode_smoke_test() {
        let options = CargoFuzzTestOptions { list: false, ..Default::default() };
        assert_eq!(
            options.execution_mode().expect("valid execution mode"),
            ExecutionMode::SmokeTest
        );
    }

    #[gtest]
    fn test_execution_mode_list_fuzz_tests() {
        let options = CargoFuzzTestOptions { list: true, ..Default::default() };
        assert_eq!(
            options.execution_mode().expect("valid execution mode"),
            ExecutionMode::ListFuzzTests
        );
    }

    #[gtest]
    fn test_cli_option_parsing_list_flag() {
        let parsed = CargoFuzzTestOptions::try_parse_from(["cargo-fuzztest", "--list"])
            .expect("--list argument should be valid CLI option");
        assert!(parsed.list);
        assert_eq!(
            parsed.execution_mode().expect("valid execution mode"),
            ExecutionMode::ListFuzzTests
        );
    }

    #[gtest]
    fn test_cli_option_parsing_default() {
        let parsed = CargoFuzzTestOptions::try_parse_from(["cargo-fuzztest"])
            .expect("empty CLI arguments should be valid");
        assert!(!parsed.list);
        assert_eq!(
            parsed.execution_mode().expect("valid execution mode"),
            ExecutionMode::SmokeTest
        );
    }

    #[gtest]
    fn test_cli_option_parsing_replay_id_success() {
        let parsed = CargoFuzzTestOptions::try_parse_from([
            "cargo-fuzztest",
            "--replay-id",
            "crash_12345",
            "--corpus-db",
            "/tmp/corpus_db",
            "--centipede-binary-path",
            "/custom/centipede",
        ])
        .expect("valid replay options should parse successfully");

        assert_eq!(parsed.fuzztest_options.replay_id.as_deref(), Some("crash_12345"));
        assert_eq!(parsed.fuzztest_options.corpus_db.as_deref(), Some("/tmp/corpus_db"));

        let mode = parsed.execution_mode().expect("valid execution mode");
        assert_eq!(
            mode,
            ExecutionMode::ReplayCrash(ReplayCrashOptions { replay_id: "crash_12345".to_string() })
        );
    }

    #[gtest]
    fn test_execution_mode_replay_id_missing_corpus_db_errors() {
        let options = CargoFuzzTestOptions {
            fuzztest_options: FuzzTestOptions {
                replay_id: Some("crash_12345".to_string()),
                ..Default::default()
            },
            centipede_binary_path: Some("/custom/centipede".to_string()),
            ..Default::default()
        };
        let err = options.execution_mode().expect_err("missing corpus-db should cause error");
        assert!(err.to_string().contains("`--corpus-db` needs to be specified"));
    }

    #[gtest]
    fn test_execution_mode_replay_id_missing_centipede_binary_path_errors() {
        let options = CargoFuzzTestOptions {
            fuzztest_options: FuzzTestOptions {
                replay_id: Some("crash_12345".to_string()),
                corpus_db: Some("/tmp/corpus_db".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        let err =
            options.execution_mode().expect_err("missing centipede-binary-path should cause error");
        assert!(err.to_string().contains("`--centipede-binary-path` needs to be specified"));
    }

    #[gtest]
    fn test_build_run_command_replay_crash() {
        let options = CargoFuzzTestOptions {
            fuzztest_options: FuzzTestOptions {
                replay_id: Some("crash_12345".to_string()),
                corpus_db: Some("/tmp/corpus_db".to_string()),
                ..Default::default()
            },
            centipede_binary_path: Some("/custom/centipede".to_string()),
            ..Default::default()
        };
        let runner = FuzztestRunner::new("x86_64-unknown-linux-gnu".to_string(), options);
        let cmd =
            runner.build_run_command(Path::new("/tmp/test_bin")).expect("should build run command");

        let envs: Vec<(String, Option<String>)> = cmd
            .get_envs()
            .map(|(k, v)| {
                (k.to_string_lossy().to_string(), v.map(|s| s.to_string_lossy().to_string()))
            })
            .collect();

        assert!(envs.contains(&("FUZZTEST_REPLAY_ID".to_string(), Some("crash_12345".to_string()))));
        assert!(
            envs.contains(&("FUZZTEST_CORPUS_DB".to_string(), Some("/tmp/corpus_db".to_string())))
        );
        assert!(envs.contains(&(
            "FUZZTEST_CENTIPEDE_BINARY_PATH".to_string(),
            Some("/custom/centipede".to_string())
        )));
    }
}
