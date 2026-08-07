use crate::internal::FuzzTestRegistration;
use ::engine::engine_ffi;
use anyhow::Context;
use clap::Parser;
use std::ffi::CString;
use std::ffi::OsString;
use std::path::Path;
use std::sync::OnceLock;
use tempfile::{NamedTempFile, TempDir};

pub use fuzztest_options::{
    ExecutionMode, FuzzFor, FuzzOptions, FuzzTestOptions, ReplayCorpusOptions, ReplayCrashOptions,
    TimeBudgetType,
};

/// Returns a lazily-initialized static reference to the global `FuzzTestOptions`.
pub fn get_fuzztest_options() -> &'static FuzzTestOptions {
    static OPTIONS: OnceLock<FuzzTestOptions> = OnceLock::new();
    // We parse FuzzTestOptions from an empty iterator so that clap would parse the options only
    // from environment variables (like `FUZZTEST_FUZZ_FOR` etc.). We (currently) do not envisage
    // support for passing flags on cli as the Rust's libtest harness does not support custom
    // flags.
    OPTIONS.get_or_init(|| FuzzTestOptions::parse_from(std::iter::empty::<OsString>()))
}

trait ExecutionModeExt {
    /// Prepares the concrete `ExecutionAction` payload for execution by building any required
    /// `CentipedeArgs` or temporary runtime assets.
    fn prepare_action(
        &self,
        options: &FuzzTestOptions,
        current_test_name: Option<&str>,
    ) -> anyhow::Result<ExecutionAction>;
}

impl ExecutionModeExt for ExecutionMode {
    /// Prepares the concrete `ExecutionAction` payload for execution by building any required
    /// `CentipedeArgs` or temporary runtime assets.
    fn prepare_action(
        &self,
        options: &FuzzTestOptions,
        current_test_name: Option<&str>,
    ) -> anyhow::Result<ExecutionAction> {
        match self {
            ExecutionMode::SmokeTest => Ok(ExecutionAction::SmokeTest),
            ExecutionMode::Fuzz(_)
            | ExecutionMode::ReplayCrash(_)
            | ExecutionMode::ReplayCorpus(_) => {
                let centipede_args =
                    CentipedeArgs::from_execution_mode(self, options, current_test_name, None)?
                        .context(
                            "while attempting to build CentipedeArgs for standalone execution mode",
                        )?;
                Ok(ExecutionAction::Standalone(centipede_args))
            }
            ExecutionMode::ReplayAllCrashes => {
                let list_file = NamedTempFile::new()
                    .context("while attempting to create temp file for ReplayAllCrashes")?;
                let centipede_args = CentipedeArgs::from_execution_mode(
                    self,
                    options,
                    current_test_name,
                    Some(list_file.path()),
                )?
                .context("while attempting to build CentipedeArgs for replay all crashes mode")?;
                Ok(ExecutionAction::ReplayAllCrashes { args: centipede_args, list_file })
            }
            ExecutionMode::ListFuzzTests => {
                anyhow::bail!("ListFuzzTest mode is supported only in cargo-fuzztest");
            }
        }
    }
}

/// The prepared, ready-to-run execution payload passed to the test worker.
///
/// This enum bridges parsed domain intent (`ExecutionMode`) with the concrete runtime
/// assets (`CentipedeArgs`, temporary files, workdir paths) needed to execute the test run.
#[derive(Debug)]
pub enum ExecutionAction {
    /// Run as a smoke test (regular unit test) with random inputs for a short duration.
    SmokeTest,

    /// Run in standalone mode, invoking the Centipede fuzzing controller.
    Standalone(CentipedeArgs),

    /// Replay all crash IDs from the database (carries `list_file` for worker post-processing).
    ReplayAllCrashes { args: CentipedeArgs, list_file: NamedTempFile },
}

/// Encapsulates command-line arguments and lifetime holders for Centipede execution.
#[derive(Debug)]
pub struct CentipedeArgs {
    // Holds the owned C-compatible strings. We must keep these alive because the `views`
    // field contains pointers into the memory owned by these `CString`s.
    _c_strings: Vec<CString>,

    // The (optional) TempDir instance which is to be used as a workdir by centipede.
    // We keep the ownership here so that it is not cleaned while the centipede execution is still
    // in progress.
    _temp_workdir: Option<TempDir>,

    // FFI-compatible views into the arguments in `_c_strings`. These are passed across
    // the FFI boundary to Centipede.
    views: Vec<engine_ffi::FuzzTestBytesView>,
}

impl CentipedeArgs {
    fn new(args: Vec<CString>, temp_workdir: Option<TempDir>) -> Self {
        let views = args
            .iter()
            .map(|arg| engine_ffi::FuzzTestBytesView::from_bytes(arg.as_bytes()))
            .collect();

        Self { _c_strings: args, _temp_workdir: temp_workdir, views }
    }

    /// Decides if Centipede needs to be invoked based on the execution mode,
    /// and constructs the appropriate arguments for it if so.
    ///
    /// Returns `Ok(Some(args))` if Centipede should be invoked, `Ok(None)` for `SmokeTest`,
    /// or `Err` if argument generation fails.
    pub fn from_execution_mode(
        mode: &ExecutionMode,
        options: &FuzzTestOptions,
        current_test_name: Option<&str>,
        list_file_path: Option<&Path>,
    ) -> anyhow::Result<Option<Self>> {
        let mode_opts = match mode {
            ExecutionMode::SmokeTest => return Ok(None),
            other => other,
        };

        let mut args = Vec::new();
        let mut add_arg = |arg: String| -> anyhow::Result<()> {
            args.push(CString::new(arg).context("while attempting to create CString arg")?);
            Ok(())
        };

        // ==============================================================================
        // 1. Common Base Arguments (Required across all Centipede executions)
        // ==============================================================================
        let argv0 = std::env::args().next().context("while attempting to get argv[0]")?;

        if let Some(test_name) = current_test_name {
            add_arg(format!("--binary={argv0} {test_name} --exact --nocapture"))?;
            let normalized_test_name = test_name.replace("::", ".");
            add_arg(format!("--test_name={normalized_test_name}"))?;
        } else {
            // We append the filter for fuzztests mod so that only fuzztests are executed and not unit tests.
            add_arg(format!("--binary={argv0} __fuzztest_mod__ --nocapture"))?;
        }

        // Binary identifier is the same as the binary path (stripped of leading slash)
        let binary_id = argv0.strip_prefix('/').unwrap_or(&argv0);
        add_arg(format!("--fuzztest_binary_identifier={binary_id}"))?;

        add_arg("--populate_binary_info=false".to_string())?;
        add_arg("--fork_server=false".to_string())?;

        add_arg(format!("--print_runner_log={}", options.print_subprocess_log))?;

        // Add a dummy hash so as to avoid Centipede computing the hash of the binary.
        add_arg("--binary_hash=DUMMY_HASH".to_string())?;

        // ==============================================================================
        // 2. Common Working Directory & Corpus Database Resolution
        // ==============================================================================
        let (opt_corpusdb, opt_workdir_root, opt_workdir) =
            get_corpusdb_and_workdir_root_and_workdir(options)
                .context("while attempting to resolve corpus and workdir options")?;

        if let Some(corpus_db) = opt_corpusdb {
            add_arg(format!("--fuzztest_corpus_database={corpus_db}"))?;
        }

        if let Some(workdir_root) = opt_workdir_root {
            add_arg(format!("--fuzztest_workdir_root={workdir_root}"))?;
        }

        if let Some(temp_workdir) = &opt_workdir {
            let workdir_path = temp_workdir
                .path()
                .to_str()
                .context("while attempting to convert temp dir path to str")?
                .to_string();
            add_arg(format!("--workdir={workdir_path}"))?;
        }

        // ==============================================================================
        // 3. Common Environment Variables Differential
        // ==============================================================================
        let env_diff = Self::default_env_diff();
        add_arg(format!("--env_diff_for_binaries={}", env_diff.join(",")))?;

        // ==============================================================================
        // 4. Mode-Specific Arguments
        // ==============================================================================
        match mode_opts {
            ExecutionMode::Fuzz(fuzz_opts) => {
                match &fuzz_opts.fuzz_for {
                    FuzzFor::Indefinitely => {
                        // not specifying `--stop_after` means to run indefinitely.
                    }
                    FuzzFor::Duration(duration) => {
                        if opt_corpusdb.is_some() {
                            add_arg(format!("--fuzztest_time_limit_per_test={duration}"))?;
                        } else {
                            add_arg(format!("--stop_after={duration}"))?;
                        }
                    }
                }
                if let Some(jobs) = &fuzz_opts.jobs {
                    add_arg(format!("--j={jobs}"))?;
                }
            }
            ExecutionMode::ReplayCrash(replay_opts) => {
                add_arg("--replay_crash".to_string())?;
                add_arg(format!("--crash_id={}", replay_opts.replay_id))?;
                add_arg("--exit_on_crash".to_string())?;
            }
            ExecutionMode::ReplayAllCrashes => {
                let path = list_file_path
                    .context("while attempting to get list_file path for ReplayAllCrashes")?;
                add_arg("--list_crash_ids=true".to_string())?;
                add_arg(format!("--list_crash_ids_file={}", path.display()))?;
            }
            ExecutionMode::ReplayCorpus(replay_corpus_opts) => {
                let time_limit = match replay_corpus_opts.time_budget_type {
                    TimeBudgetType::PerTest => replay_corpus_opts.replay_corpus_for,
                    TimeBudgetType::Total => {
                        let num_tests = inventory::iter::<FuzzTestRegistration>().count();
                        if num_tests == 0 {
                            replay_corpus_opts.replay_corpus_for
                        } else {
                            (*replay_corpus_opts.replay_corpus_for.as_ref() / (num_tests as u32))
                                .into()
                        }
                    }
                };
                add_arg("--fuzztest_only_replay=true".to_string())?;
                add_arg("--fuzztest_replay_coverage_inputs=true".to_string())?;
                add_arg("--load_shards_only=true".to_string())?;
                add_arg(format!("--fuzztest_time_limit_per_test={time_limit}"))?;
            }
            ExecutionMode::SmokeTest => unreachable!(),
            ExecutionMode::ListFuzzTests => unreachable!(),
        }

        Ok(Some(Self::new(args, opt_workdir)))
    }

    /// Generates the default environment variable diff list.
    ///
    /// This replicates the logic in `GetEnvDiffForBinaries` from
    /// `fuzztest/internal/centipede_adaptor.cc`.
    ///
    /// When Centipede spawns the test binary as a subprocess, we do not want it to inherit
    /// environment variables set by the test harness (like Blaze/Bazel). Inheriting these
    /// could cause the subprocess to think it's running in a sharded environment, try to
    /// write to restricted output files, or trigger other harness-specific behavior that
    /// interferes with fuzzing.
    fn default_env_diff() -> Vec<String> {
        let mut env_diff = vec![
            "-TEST_DIAGNOSTICS_OUTPUT_DIR".to_string(),
            "-TEST_INFRASTRUCTURE_FAILURE_FILE".to_string(),
            "-TEST_LOGSPLITTER_OUTPUT_FILE".to_string(),
            "-TEST_PREMATURE_EXIT_FILE".to_string(),
            "-TEST_RANDOM_SEED".to_string(),
            "-TEST_RUN_NUMBER".to_string(),
            "-TEST_SHARD_INDEX".to_string(),
            "-TEST_SHARD_STATUS_FILE".to_string(),
            "-TEST_TOTAL_SHARDS".to_string(),
            "-TEST_UNDECLARED_OUTPUTS_ANNOTATIONS_DIR".to_string(),
            "-TEST_UNDECLARED_OUTPUTS_DIR".to_string(),
            "-TEST_WARNINGS_OUTPUT_FILE".to_string(),
            "-GTEST_OUTPUT".to_string(),
            "-XML_OUTPUT_FILE".to_string(),
        ];

        env_diff
    }

    /// Exposes the FFI-compatible argument views vector for C++ Centipede binding.
    pub fn as_bytes_views(&self) -> engine_ffi::FuzzTestBytesViews {
        engine_ffi::FuzzTestBytesViews { views: self.views.as_ptr(), count: self.views.len() }
    }
}

/// Determines the `ExecutionAction` for the given test name by inspecting global options.
pub fn determine_execution_action(current_test_name: Option<&str>) -> ExecutionAction {
    determine_execution_action_internal(get_fuzztest_options(), current_test_name)
}

fn determine_execution_action_internal(
    options: &FuzzTestOptions,
    current_test_name: Option<&str>,
) -> ExecutionAction {
    ExecutionMode::from_fuzztest_options(options)
        .prepare_action(options, current_test_name)
        .expect("failed to prepare execution action from fuzztest options")
}

fn get_corpusdb_and_workdir_root_and_workdir(
    options: &FuzzTestOptions,
) -> anyhow::Result<(Option<&str>, Option<&str>, Option<TempDir>)> {
    let corpus_db = options.corpus_db.as_deref();
    let workdir_root = options.workdir_root.as_deref();

    if let Some(corpus_db) = corpus_db {
        if let Some(workdir_root) = workdir_root {
            Ok((Some(corpus_db), Some(workdir_root), None))
        } else {
            let temp_dir =
                TempDir::new().context("while attempting to create temporary working directory")?;
            Ok((Some(corpus_db), None, Some(temp_dir)))
        }
    } else {
        if workdir_root.is_some() {
            anyhow::bail!("NOT ALLOWED: workdir_root provided without corpus_db")
        } else {
            let temp_dir =
                TempDir::new().context("while attempting to create temporary working directory")?;
            Ok((None, None, Some(temp_dir)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;
    use std::ffi::OsString;

    #[gtest]
    fn test_fuzz_options_parsing_env() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_FUZZ_FOR", "5s");
        }

        let options = FuzzTestOptions::parse_from(std::iter::empty::<OsString>());

        expect_true!(options.fuzz_for.is_some());
        expect_that!(
            ExecutionMode::from_fuzztest_options(&options),
            matches_pattern!(ExecutionMode::Fuzz(_))
        );

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_FUZZ_FOR");
        }
    }

    #[gtest]
    fn test_fuzz_options_parsing_indefinite_env() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_FUZZ_FOR", "inf");
        }

        let options = FuzzTestOptions::parse_from(std::iter::empty::<OsString>());

        expect_that!(options.fuzz_for, eq(Some(FuzzFor::Indefinitely)));
        let mode = ExecutionMode::from_fuzztest_options(&options);
        let ExecutionMode::Fuzz(fuzz_opts) = mode else {
            panic!("Expected ExecutionMode::Fuzz");
        };
        expect_that!(fuzz_opts.fuzz_for, eq(FuzzFor::Indefinitely));

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_FUZZ_FOR");
        }
    }

    #[gtest]
    fn test_determine_execution_action_standalone_indefinite() {
        let options =
            FuzzTestOptions { fuzz_for: Some(FuzzFor::Indefinitely), ..Default::default() };
        let action = determine_execution_action_internal(&options, Some("my_mod::my_test"));

        let ExecutionAction::Standalone(args) = action else {
            panic!("Expected Standalone action");
        };

        let args_str: Vec<&str> =
            args._c_strings.iter().map(|s| s.to_str().expect("invalid utf8")).collect();

        // When running indefinitely, --stop_after must be omitted so Centipede runs until interrupted.
        expect_false!(args_str.iter().any(|s| s.starts_with("--stop_after=")));
        expect_true!(args_str.contains(&"--test_name=my_mod.my_test"));
    }

    #[gtest]
    fn test_determine_execution_action_smoke_test() {
        let options = FuzzTestOptions::default();
        let action = determine_execution_action_internal(&options, Some("my_mod::my_test"));
        assert!(matches!(action, ExecutionAction::SmokeTest));
    }

    #[gtest]
    fn test_determine_execution_action_standalone() {
        let expected_duration = "10s".parse().unwrap();
        let options = FuzzTestOptions {
            fuzz_for: Some(FuzzFor::Duration(expected_duration)),
            ..Default::default()
        };
        let action = determine_execution_action_internal(&options, Some("my_mod::my_test"));

        let ExecutionAction::Standalone(args) = action else {
            panic!("Expected Standalone action");
        };

        expect_that!(args._c_strings.len(), eq(args.views.len()));

        let args_str: Vec<&str> =
            args._c_strings.iter().map(|s| s.to_str().expect("invalid utf8")).collect();

        expect_true!(args_str
            .iter()
            .any(|s| s.starts_with("--binary=") && s.contains("my_mod::my_test --exact")));

        expect_true!(args_str.contains(&"--stop_after=10s"));
        expect_true!(args_str.contains(&"--test_name=my_mod.my_test"));
        expect_true!(args_str.iter().any(|s| s.starts_with("--env_diff_for_binaries=")));

        // Verify that a temporary workdir was created and passed as an argument.
        expect_true!(args._temp_workdir.is_some());
        let temp_workdir_path = args._temp_workdir.as_ref().unwrap().path().to_str().unwrap();
        let expected_workdir_arg = format!("--workdir={}", temp_workdir_path);
        expect_true!(args_str.contains(&expected_workdir_arg.as_str()));
    }

    #[gtest]
    fn test_centipede_args_binary_identifier() {
        let expected_duration = "1s".parse().unwrap();
        let options = FuzzTestOptions {
            fuzz_for: Some(FuzzFor::Duration(expected_duration)),
            ..Default::default()
        };
        let action = determine_execution_action_internal(&options, Some("my_mod::my_test"));

        let ExecutionAction::Standalone(args) = action else {
            panic!("Expected Standalone action");
        };

        let args_str: Vec<&str> =
            args._c_strings.iter().map(|s| s.to_str().expect("invalid utf8")).collect();

        let argv0 = std::env::args().next().expect("get argv[0]");
        let binary_id = argv0.strip_prefix('/').unwrap_or(&argv0);
        let expected_binary_id_arg = format!("--fuzztest_binary_identifier={binary_id}");

        expect_true!(args_str.contains(&expected_binary_id_arg.as_str()));
    }

    #[gtest]
    fn test_centipede_args_jobs() {
        let expected_duration = "1s".parse().expect("failed to parse duration");
        let options_no_jobs = FuzzTestOptions {
            fuzz_for: Some(FuzzFor::Duration(expected_duration)),
            ..Default::default()
        };
        let action_no_jobs =
            determine_execution_action_internal(&options_no_jobs, Some("my_mod::my_test"));
        let ExecutionAction::Standalone(args_no_jobs) = action_no_jobs else {
            panic!("Expected Standalone action");
        };
        let args_str_no_jobs: Vec<&str> =
            args_no_jobs._c_strings.iter().map(|s| s.to_str().expect("invalid utf8")).collect();
        assert!(!args_str_no_jobs.iter().any(|s| s.starts_with("--j=")));

        let options_with_jobs = FuzzTestOptions {
            fuzz_for: Some(FuzzFor::Duration(expected_duration)),
            jobs: Some(4),
            ..Default::default()
        };
        let action_with_jobs =
            determine_execution_action_internal(&options_with_jobs, Some("my_mod::my_test"));
        let ExecutionAction::Standalone(args_with_jobs) = action_with_jobs else {
            panic!("Expected Standalone action");
        };
        let args_str_with_jobs: Vec<&str> =
            args_with_jobs._c_strings.iter().map(|s| s.to_str().expect("invalid utf8")).collect();
        assert!(args_str_with_jobs.contains(&"--j=4"));
    }

    #[gtest]
    fn test_default_env_diff_set() {
        let duration = "1s".parse().unwrap();
        let options =
            FuzzTestOptions { fuzz_for: Some(FuzzFor::Duration(duration)), ..Default::default() };
        let action = determine_execution_action_internal(&options, Some("my_mod::my_test"));
        let ExecutionAction::Standalone(args) = action else {
            panic!("Expected Standalone action");
        };

        let args_str: Vec<&str> =
            args._c_strings.iter().map(|s| s.to_str().expect("invalid utf8")).collect();

        let env_diff_arg = args_str
            .iter()
            .find(|s| s.starts_with("--env_diff_for_binaries="))
            .expect("missing --env_diff_for_binaries arg");

        expect_true!(env_diff_arg.contains("-TEST_SHARD_INDEX"));
        expect_true!(env_diff_arg.contains("-XML_OUTPUT_FILE"));
        expect_true!(env_diff_arg.contains("-GTEST_OUTPUT"));
    }

    #[gtest]
    fn test_determine_execution_action_replay_crash_id() {
        let options = FuzzTestOptions {
            replay_id: Some("my_crash_123".to_string()),
            corpus_db: Some("/tmp/corpus_db".to_string()),
            ..Default::default()
        };
        let action = determine_execution_action_internal(&options, Some("my_mod::my_test"));

        let ExecutionAction::Standalone(args) = action else {
            panic!("Expected Standalone action");
        };

        let args_str: Vec<&str> =
            args._c_strings.iter().map(|s| s.to_str().expect("invalid utf8")).collect();

        expect_true!(args_str.contains(&"--replay_crash"));
        expect_true!(args_str.contains(&"--crash_id=my_crash_123"));
        expect_true!(args_str.contains(&"--fuzztest_corpus_database=/tmp/corpus_db"));
        expect_true!(args_str.contains(&"--test_name=my_mod.my_test"));
        expect_true!(args_str.iter().any(|s| s.starts_with("--workdir=")));
    }

    #[gtest]
    fn test_determine_execution_action_replay_findings() {
        let options = FuzzTestOptions {
            replay_findings: true,
            corpus_db: Some("/tmp/corpus_db".to_string()),
            ..Default::default()
        };
        let action = determine_execution_action_internal(&options, Some("my_mod::my_test"));

        let ExecutionAction::ReplayAllCrashes { args, list_file } = action else {
            panic!("Expected ReplayAllCrashes action");
        };

        let args_str: Vec<&str> =
            args._c_strings.iter().map(|s| s.to_str().expect("invalid utf8")).collect();

        expect_true!(args_str.contains(&"--list_crash_ids=true"));
        expect_true!(args_str
            .contains(&format!("--list_crash_ids_file={}", list_file.path().display()).as_str()));
        expect_true!(args_str.contains(&"--fuzztest_corpus_database=/tmp/corpus_db"));
        expect_true!(args_str.iter().any(|s| s.starts_with("--workdir=")));
        expect_true!(args_str.contains(&"--test_name=my_mod.my_test"));
    }

    #[gtest]
    fn test_determine_execution_action_replay_corpus() {
        let expected_duration = "10s".parse().expect("failed to parse duration");
        let options = FuzzTestOptions {
            replay_corpus_for: Some(expected_duration),
            time_budget_type: TimeBudgetType::PerTest,
            ..Default::default()
        };
        let action = determine_execution_action_internal(&options, Some("my_mod::my_test"));

        let ExecutionAction::Standalone(args) = action else {
            panic!("Expected Standalone action");
        };

        let args_str: Vec<&str> =
            args._c_strings.iter().map(|s| s.to_str().expect("invalid utf8")).collect();

        assert!(args_str
            .iter()
            .any(|s| s.starts_with("--binary=") && s.contains("my_mod::my_test --exact")));
        assert!(args_str.contains(&"--fuzztest_only_replay=true"));
        assert!(args_str.contains(&"--fuzztest_time_limit_per_test=10s"));
    }

    #[gtest]
    fn test_determine_execution_action_replay_corpus_total_budget() {
        let expected_duration = "10s".parse().expect("failed to parse duration");
        let options = FuzzTestOptions {
            replay_corpus_for: Some(expected_duration),
            time_budget_type: TimeBudgetType::Total,
            ..Default::default()
        };
        let action = determine_execution_action_internal(&options, Some("my_mod::my_test"));

        let ExecutionAction::Standalone(args) = action else {
            panic!("Expected Standalone action");
        };

        let args_str: Vec<&str> =
            args._c_strings.iter().map(|s| s.to_str().expect("invalid utf8")).collect();

        let num_tests = inventory::iter::<FuzzTestRegistration>().count();
        let expected_limit = if num_tests == 0 {
            expected_duration
        } else {
            (*expected_duration.as_ref() / (num_tests as u32)).into()
        };
        let expected_limit_str = format!("--fuzztest_time_limit_per_test={}", expected_limit);

        assert!(args_str.contains(&expected_limit_str.as_str()));
    }

    #[gtest]
    fn test_determine_execution_action_replay_corpus_no_test_name() {
        let expected_duration = "10s".parse().expect("failed to parse duration");
        let options = FuzzTestOptions {
            replay_corpus_for: Some(expected_duration),
            time_budget_type: TimeBudgetType::PerTest,
            ..Default::default()
        };
        let action = determine_execution_action_internal(&options, None);

        let ExecutionAction::Standalone(args) = action else {
            panic!("Expected Standalone action");
        };

        let args_str: Vec<&str> =
            args._c_strings.iter().map(|s| s.to_str().expect("invalid utf8")).collect();

        assert!(args_str.iter().any(|s| s.contains("__fuzztest_mod__")));
        assert!(args_str.contains(&"--fuzztest_only_replay=true"));
        assert!(args_str.contains(&"--fuzztest_time_limit_per_test=10s"));
        assert!(!args_str.iter().any(|s| s.starts_with("--test_name=")));
    }

    #[gtest]
    fn test_get_corpusdb_and_workdir_default_creates_temp_workdir() -> Result<()> {
        let options = FuzzTestOptions::default();
        let (corpus_db, workdir_root, workdir) =
            get_corpusdb_and_workdir_root_and_workdir(&options).or_fail()?;
        expect_true!(corpus_db.is_none());
        expect_true!(workdir_root.is_none());
        expect_true!(workdir.is_some());
        Ok(())
    }

    #[gtest]
    fn test_get_corpusdb_and_workdir_succeeds_with_corpusdb_and_workdir_root() -> Result<()> {
        let options = FuzzTestOptions {
            corpus_db: Some("/tmp/db".to_string()),
            workdir_root: Some("/tmp/root".to_string()),
            ..Default::default()
        };
        let (corpus_db, workdir_root, workdir) =
            get_corpusdb_and_workdir_root_and_workdir(&options).or_fail()?;
        expect_that!(corpus_db, eq(Some("/tmp/db")));
        expect_that!(workdir_root, eq(Some("/tmp/root")));
        expect_true!(workdir.is_none());
        Ok(())
    }

    #[gtest]
    fn test_get_corpusdb_and_workdir_succeeds_with_corpusdb_only() -> Result<()> {
        let options =
            FuzzTestOptions { corpus_db: Some("/tmp/db".to_string()), ..Default::default() };
        let (corpus_db, workdir_root, workdir) =
            get_corpusdb_and_workdir_root_and_workdir(&options).or_fail()?;
        expect_that!(corpus_db, eq(Some("/tmp/db")));
        expect_true!(workdir_root.is_none());
        expect_true!(workdir.is_some());
        Ok(())
    }

    #[gtest]
    fn test_replay_id_requires_corpus_db() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_REPLAY_ID", "my_crash_123");
            std::env::remove_var("FUZZTEST_CORPUS_DB");
        }

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_REPLAY_ID");
        }

        let err = result.expect_err("parsing should fail when corpus_db is missing");
        expect_that!(err.kind(), eq(clap::error::ErrorKind::MissingRequiredArgument));
    }

    #[gtest]
    fn test_replay_id_with_corpus_db_succeeds() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_REPLAY_ID", "my_crash_123");
            std::env::set_var("FUZZTEST_CORPUS_DB", "/tmp/corpus_db");
        }

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_REPLAY_ID");
            std::env::remove_var("FUZZTEST_CORPUS_DB");
        }

        let options =
            result.expect("parsing should succeed when both replay_id and corpus_db are present");
        expect_that!(options.replay_id.as_deref(), eq(Some("my_crash_123")));
        expect_that!(options.corpus_db.as_deref(), eq(Some("/tmp/corpus_db")));
    }

    #[gtest]
    fn test_centipede_args_fuzz_for_duration_without_corpus_db() {
        // When corpus_db is not provided, fuzzing for a fixed duration should pass --stop_after
        // to Centipede so it stops fuzzing after the specified duration.
        let duration = "1s".parse().expect("fixed test string should parse as duration");
        let options = FuzzTestOptions {
            fuzz_for: Some(FuzzFor::Duration(duration)),
            corpus_db: None,
            ..Default::default()
        };
        let action = determine_execution_action_internal(&options, Some("my_mod::my_test"));

        let ExecutionAction::Standalone(args) = action else {
            panic!("Expected Standalone action when fuzzing for duration");
        };

        let args_str: Vec<&str> = args
            ._c_strings
            .iter()
            .map(|s| s.to_str().expect("args strings should be valid UTF-8"))
            .collect();

        expect_true!(args_str.contains(&"--stop_after=1s"));
        expect_false!(args_str.iter().any(|s| s.starts_with("--fuzztest_time_limit_per_test=")));
    }

    #[gtest]
    fn test_centipede_args_fuzz_for_duration_with_corpus_db() {
        // When corpus_db is set, fuzzing for a duration should pass --fuzztest_time_limit_per_test
        // instead of --stop_after, because Centipede uses time_limit_per_test when running against
        // a corpus database.
        let duration = "1s".parse().expect("fixed test string should parse as duration");
        let options = FuzzTestOptions {
            fuzz_for: Some(FuzzFor::Duration(duration)),
            corpus_db: Some("/tmp/corpus_db".to_string()),
            ..Default::default()
        };
        let action = determine_execution_action_internal(&options, Some("my_mod::my_test"));

        let ExecutionAction::Standalone(args) = action else {
            panic!("Expected Standalone action when fuzzing with corpus_db and duration");
        };

        let args_str: Vec<&str> = args
            ._c_strings
            .iter()
            .map(|s| s.to_str().expect("args strings should be valid UTF-8"))
            .collect();

        expect_true!(args_str.contains(&"--fuzztest_time_limit_per_test=1s"));
        expect_true!(args_str.contains(&"--fuzztest_corpus_database=/tmp/corpus_db"));
        expect_false!(args_str.iter().any(|s| s.starts_with("--stop_after=")));
    }
}
