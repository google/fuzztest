use anyhow::Context;

fn get_host_target_triple() -> anyhow::Result<String> {
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

fn main() -> anyhow::Result<()> {
    let host_triple = get_host_target_triple()?;

    let cargo_bin = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = std::process::Command::new(&cargo_bin);

    // run all fuzztests
    cmd.arg("test");
    cmd.arg("__fuzztest_mod__");

    cmd.arg("--").arg("--test-threads=1");

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
        format!("CARGO_TARGET_{}_RUSTFLAGS", host_triple.to_uppercase().replace("-", "_"));
    let rustflags_value = "-Cpasses=sancov-module \
                           -Cllvm-args=-sanitizer-coverage-level=4 \
                           -Cllvm-args=-sanitizer-coverage-pc-table \
                           -Cllvm-args=-sanitizer-coverage-inline-8bit-counters \
                           -Cllvm-args=-sanitizer-coverage-trace-compares";
    cmd.env(&target_env_key, rustflags_value);

    let exit_code = {
        let status = cmd.status().context("run cargo test command")?;
        status.code().unwrap_or(1)
    };
    std::process::exit(exit_code);
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
        assert!(result.unwrap_err().to_string().contains("Failed to find 'host: ' line"));
    }

    #[test]
    fn test_get_host_target_triple_success() {
        let result = get_host_target_triple();
        assert!(result.is_ok(), "Expected to succeed on host system, got: {:?}", result);
        let triple = result.expect("get_host_target_triple should succeed on host system");
        assert!(!triple.is_empty());
        assert!(triple.contains('-'));
    }
}
