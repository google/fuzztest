// This module provides the core command-line flag and environment variable options
// structure (`FuzzTestOptions`) and domain execution modes (`ExecutionMode`).
// Both the test harness runtime and host tools (e.g. `cargo-fuzztest`) can share option parsing
// logic.

use clap::{Parser, ValueEnum};
use humantime::Duration;

/// Time budget calculation type for replay corpus mode.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeBudgetType {
    #[default]
    PerTest,
    Total,
}

/// Command-line and environment variable options parsed for the FuzzTest harness.
#[derive(Parser, Debug, Clone, Default)]
pub struct FuzzTestOptions {
    /// The working root directory.
    #[arg(env = "FUZZTEST_WORKDIR_ROOT", long)]
    pub workdir_root: Option<String>,

    /// The duration for which each test should be fuzzed.
    #[arg(env = "FUZZTEST_FUZZ_FOR", long)]
    pub fuzz_for: Option<Duration>,

    /// If true, subprocess logs are printed after every batch. Note that crash logs are always printed
    /// regardless of this flag's value.
    #[arg(env = "FUZZTEST_PRINT_SUBPROCESS_LOG", long)]
    pub print_subprocess_log: bool,

    /// Number of parallel jobs to run.
    #[arg(env = "FUZZTEST_JOBS", long)]
    pub jobs: Option<usize>,

    /// The crash ID to be replayed from the corpus database.
    ///
    /// If set, `corpus_db` must also be specified. This mode retrieves the crashing input
    /// associated with the given ID from the database and executes the property function.
    #[arg(env = "FUZZTEST_REPLAY_ID", long, requires = "corpus_db")]
    pub replay_id: Option<String>,

    /// Replay all crashing inputs from the corpus database.
    #[arg(env = "FUZZTEST_REPLAY_FINDINGS", long)]
    pub replay_findings: bool,

    /// Replay the corpus for a specified duration.
    #[arg(env = "FUZZTEST_REPLAY_CORPUS_FOR", long)]
    pub replay_corpus_for: Option<Duration>,

    /// Time budget calculation type for replay corpus mode.
    #[arg(env = "FUZZTEST_TIME_BUDGET_TYPE", long, value_enum, default_value_t = TimeBudgetType::PerTest)]
    pub time_budget_type: TimeBudgetType,

    /// The path to the corpus database.
    ///
    /// If set to non-empty, updates/queries the corpus database that contains coverage,
    /// regression, and crashing inputs for each test binary and fuzz test.
    #[arg(env = "FUZZTEST_CORPUS_DB", long)]
    pub corpus_db: Option<String>,
}

impl FuzzTestOptions {
    /// Evaluates the raw options and maps them to a strongly-typed domain `ExecutionMode`.
    ///
    /// This decouples raw environment/CLI option parsing from execution mode validation.
    pub fn execution_mode(&self) -> ExecutionMode {
        if let Some(replay_corpus_for) = self.replay_corpus_for {
            return ExecutionMode::ReplayCorpus(ReplayCorpusOptions {
                replay_corpus_for,
                time_budget_type: self.time_budget_type,
            });
        }

        if self.replay_findings {
            return ExecutionMode::ReplayAllCrashes;
        }

        if let Some(replay_id) = &self.replay_id {
            return ExecutionMode::ReplayCrash(ReplayCrashOptions { replay_id: replay_id.clone() });
        }

        if let Some(duration) = self.fuzz_for {
            return ExecutionMode::Fuzz(FuzzOptions {
                fuzz_for: FuzzFor::Duration(duration),
                jobs: self.jobs.clone(),
            });
        }

        ExecutionMode::SmokeTest
    }
}

/// Strongly-typed domain execution mode for test runs.
///
/// This enum represents the parsed high-level user intent derived from `FuzzTestOptions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionMode {
    /// Smoke test execution (regular unit test fallback).
    SmokeTest,

    /// Fuzzing mode.
    Fuzz(FuzzOptions),

    /// Replay a specific crash ID from the corpus database.
    ReplayCrash(ReplayCrashOptions),

    /// Replay all crashing inputs stored in the corpus database.
    ReplayAllCrashes,

    /// Replay corpus inputs for a specified duration.
    ReplayCorpus(ReplayCorpusOptions),
}

/// Mode-specific options for continuous fuzzing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzOptions {
    pub fuzz_for: FuzzFor,

    /// If `jobs` is `None`, we won't specify the number of jobs while invoking Centipede and it will
    /// use its own default value.
    pub jobs: Option<usize>,
}

/// The duration or limit for fuzzing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FuzzFor {
    /// Fuzz indefinitely until it is manually stopped or a crash is found.
    Indefinitely,

    /// Fuzz for a specific duration.
    Duration(Duration),
}

/// Mode-specific options for replaying a specific database crash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayCrashOptions {
    pub replay_id: String,
}

/// Mode-specific options for replaying corpus for a duration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayCorpusOptions {
    pub replay_corpus_for: Duration,
    pub time_budget_type: TimeBudgetType,
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
        expect_that!(options.execution_mode(), matches_pattern!(ExecutionMode::Fuzz(_)));

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_FUZZ_FOR");
        }
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
}
