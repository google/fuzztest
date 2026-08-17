use cargo_fuzztest::FuzztestRunner;
use std::env;
use std::path::PathBuf;

// Helper to locate compiled sample fuzz test executables across different build environments
// (Cargo tests vs Blaze/Bazel tests).
pub fn get_sample_test_bin_path(crate_name: &str) -> PathBuf {
    let test_bin_name = format!("{crate_name}_bin");

    // 1. Cargo test: Check if CARGO_BIN_EXE_<name> is set by Cargo when running integration tests.
    if let Ok(cargo_bin) = env::var(format!("CARGO_BIN_EXE_{test_bin_name}")) {
        return PathBuf::from(cargo_bin);
    }

    // 2. Bazel/Blaze test: Fall back to TEST_SRCDIR and TEST_WORKSPACE.
    if let Ok(src_dir) = env::var("TEST_SRCDIR") {
        let test_workspace = env::var("TEST_WORKSPACE").unwrap_or_else(|_| {
            "_main".to_string()
        });

        let relative_binary_path =
        format!("rust/cargo_fuzztest/{test_bin_name}");

        let blaze_path = PathBuf::from(src_dir).join(test_workspace).join(relative_binary_path);
        assert!(blaze_path.exists());
        return blaze_path;
    }

    // 3. Cargo test fallback: Query compiled test executable path via Cargo JSON compiler messages.
    if env::var("CARGO_MANIFEST_DIR").is_ok() {
        let cargo_bin = env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
        let output = std::process::Command::new(cargo_bin)
            .args(["test", "--no-run", "--message-format=json", "--test", &test_bin_name])
            .output()
            .expect("cargo test compilation command should execute successfully");
        assert!(output.status.success());

        let json_stdout = String::from_utf8_lossy(&output.stdout);
        if let Ok(exe) = FuzztestRunner::parse_compiler_messages(&json_stdout) {
            return exe;
        }
    }

    panic!("Could not locate {test_bin_name} via CARGO_BIN_EXE, TEST_SRCDIR, or Cargo compiler messages");
}
