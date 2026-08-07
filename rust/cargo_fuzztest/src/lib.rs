use anyhow::{Context, Result};
use clap::Parser;
pub use fuzztest_options::FuzzTestOptions;
use std::path::{Path, PathBuf};
use std::process::Command;

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
pub fn parse_cli_options() -> FuzzTestOptions {
    let mut args: Vec<std::ffi::OsString> = std::env::args_os().collect();
    if args.len() > 1 && args[1] == "fuzztest" {
        args.remove(1);
    }
    FuzzTestOptions::parse_from(args)
}

pub struct FuzztestRunner {
    pub host_triple: String,
    pub options: FuzzTestOptions,
}

impl FuzztestRunner {
    pub fn new(host_triple: String, options: FuzzTestOptions) -> Self {
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
        let mut rustflags_value = std::env::var(&target_env_key)
            .or_else(|_| std::env::var("RUSTFLAGS"))
            .unwrap_or_default();
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
    pub fn build_run_command(&self, test_binary: &Path) -> Command {
        let mut cmd = Command::new(test_binary);
        cmd.arg("__fuzztest_mod__");
        cmd.arg("--test-threads=1");
        cmd
    }

    /// Runs the tool in two steps:
    /// 1. build the test binary
    /// 2. run the test binary
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
        let mut run_cmd = self.build_run_command(&test_binary);
        let status =
            run_cmd.status().context("while attempting to execute compiled test binary")?;

        Ok(status.code().unwrap_or(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
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

    #[test]
    fn test_parse_host_triple_missing_host() {
        let stdout = "rustc 1.75.0 (82e5872f3 2023-12-21)\n\
                      binary: rustc\n";
        let result = parse_host_triple(stdout);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Failed to find 'host: '"));
    }
}
