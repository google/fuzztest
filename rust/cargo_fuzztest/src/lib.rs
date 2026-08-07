use anyhow::{Context, Result};
use clap::Parser;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Parser, Debug, Clone, Default)]
pub struct CargoFuzzTestOptions {
    /// List all fuzz tests in the crate without running them.
    #[arg(long)]
    pub list: bool,
}

impl CargoFuzzTestOptions {
    /// Returns the active domain `ExecutionMode` derived from CLI options.
    pub fn execution_mode(&self) -> ExecutionMode {
        if self.list {
            return ExecutionMode::ListFuzzTests;
        }
        ExecutionMode::SmokeTest
    }
}

/// Domain execution mode for `cargo-fuzztest`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionMode {
    /// List all discovered fuzz tests without running them.
    ListFuzzTests,

    SmokeTest,
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

        // set flags for sancov instrumentation
        let mut rustflags = std::env::var("RUSTFLAGS").unwrap_or_default();
        rustflags.push_str(
            " -Cpasses=sancov-module \
              -Cllvm-args=-sanitizer-coverage-level=4 \
              -Cllvm-args=-sanitizer-coverage-trace-pc-guard \
              -Cllvm-args=-sanitizer-coverage-pc-table \
              -Cllvm-args=-sanitizer-coverage-trace-compares",
        );
        cmd.env("RUSTFLAGS", rustflags);

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
                let is_compiler_artifact = val["reason"] == "compiler-artifact";
                let is_test_profile = val["profile"]["test"].as_bool().unwrap_or(false);

                if is_compiler_artifact && is_test_profile {
                    if let Some(exe) = val["executable"].as_str() {
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
    pub fn build_run_command(&self, test_binary: &Path) -> Command {
        let mut cmd = Command::new(test_binary);
        cmd.arg("__fuzztest_mod__");

        let mode = self.options.execution_mode();
        match mode {
            ExecutionMode::ListFuzzTests => {
                cmd.arg("--list");
            }
            ExecutionMode::SmokeTest => {
                // nothing to be done
            }
        }

        cmd
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

        // 2. execute command according to the selected execution mode
        let mut run_cmd = self.build_run_command(&test_binary);
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
        let cmd = runner.build_run_command(Path::new("/tmp/test_bin"));
        let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().to_string()).collect();
        assert_eq!(args, vec!["__fuzztest_mod__"]);
    }

    #[gtest]
    fn test_build_run_command_list() {
        let options = CargoFuzzTestOptions { list: true };
        let runner = FuzztestRunner::new("x86_64-unknown-linux-gnu".to_string(), options);
        let cmd = runner.build_run_command(Path::new("/tmp/test_bin"));
        let args: Vec<String> = cmd.get_args().map(|a| a.to_string_lossy().to_string()).collect();
        assert_eq!(args, vec!["__fuzztest_mod__", "--list"]);
    }

    #[gtest]
    fn test_execution_mode_smoke_test() {
        let options = CargoFuzzTestOptions { list: false };
        assert_eq!(options.execution_mode(), ExecutionMode::SmokeTest);
    }

    #[gtest]
    fn test_execution_mode_list_fuzz_tests() {
        let options = CargoFuzzTestOptions { list: true };
        assert_eq!(options.execution_mode(), ExecutionMode::ListFuzzTests);
    }

    #[gtest]
    fn test_cli_option_parsing_list_flag() {
        let parsed = CargoFuzzTestOptions::try_parse_from(["cargo-fuzztest", "--list"])
            .expect("--list argument should be valid CLI option");
        assert!(parsed.list);
        assert_eq!(parsed.execution_mode(), ExecutionMode::ListFuzzTests);
    }

    #[gtest]
    fn test_cli_option_parsing_default() {
        let parsed = CargoFuzzTestOptions::try_parse_from(["cargo-fuzztest"])
            .expect("empty CLI arguments should be valid");
        assert!(!parsed.list);
        assert_eq!(parsed.execution_mode(), ExecutionMode::SmokeTest);
    }
}
