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

//! This module provides the core command-line flag and environment variable options
//! structure (`FuzzTestOptions`) and domain execution modes (`ExecutionMode`).

#![deny(clippy::absolute_paths)]
#![deny(unused_imports)]

use anyhow::Context;
use clap::{Parser, ValueEnum};
use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;
use std::str::FromStr;

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
    ///
    /// Accepts a human-readable duration (e.g., `5s`, `10m`, `1h`) or `inf` / `infinity`
    /// to fuzz indefinitely until a crash is found or it is stopped manually.
    #[arg(env = "FUZZTEST_FUZZ_FOR", long)]
    pub fuzz_for: Option<RunDuration>,

    /// If true, subprocess logs are printed after every batch. Note that crash logs are always
    /// printed regardless of this flag's value.
    #[arg(env = "FUZZTEST_PRINT_SUBPROCESS_LOG", long)]
    pub print_subprocess_log: bool,

    /// Number of parallel jobs to run.
    #[arg(env = "FUZZTEST_JOBS", long)]
    pub jobs: Option<usize>,

    /// List all crash IDs stored in the corpus database.
    #[arg(
        env = "FUZZTEST_LIST_CRASH_IDS",
        long,
        requires = "corpus_db",
        requires = "list_crash_ids_file"
    )]
    pub list_crash_ids: bool,

    /// The output file path where listed crash IDs will be written.
    #[arg(
        env = "FUZZTEST_LIST_CRASH_IDS_FILE",
        long,
        requires = "corpus_db",
        requires = "list_crash_ids"
    )]
    pub list_crash_ids_file: Option<String>,

    /// The crash ID to be replayed from the corpus database.
    ///
    /// If set, `corpus_db` must also be specified. This mode retrieves the crashing input
    /// associated with the given ID from the database and executes the property function.
    #[arg(env = "FUZZTEST_REPLAY_ID", long, requires = "corpus_db")]
    pub replay_id: Option<String>,

    /// Replay all crashing inputs from the corpus database.
    #[arg(env = "FUZZTEST_REPLAY_FINDINGS", long, requires = "corpus_db")]
    pub replay_findings: bool,

    /// Replay the corpus for a specified duration.
    ///
    /// Accepts a human-readable duration (e.g., `5s`, `10m`, `1h`) or `inf` / `infinity`
    /// to replay indefinitely until stopped manually.
    #[arg(env = "FUZZTEST_REPLAY_CORPUS_FOR", long, requires = "corpus_db")]
    pub replay_corpus_for: Option<RunDuration>,

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

    /// List crash IDs stored in the corpus database.
    ListCrashIds(ListCrashIdsOptions),

    /// List all discovered fuzz tests without running them.
    /// Currently only supported via `cargo-fuzztest`.
    ListFuzzTests,
}

impl ExecutionMode {
    /// Evaluates the raw options and maps them to a strongly-typed domain `ExecutionMode`.
    ///
    /// This decouples raw environment/CLI option parsing from execution mode validation.
    pub fn from_fuzztest_options(options: &FuzzTestOptions) -> ExecutionMode {
        if options.list_crash_ids {
            return ExecutionMode::ListCrashIds(ListCrashIdsOptions {
                // TODO(the-shank): If a crash-ids file is not provided, write to stdout.
                list_crash_ids_file: options
                    .list_crash_ids_file
                    .clone()
                    .expect("list_crash_ids_file should be set when list_crash_ids"),
            });
        }

        if let Some(replay_corpus_for) = options.replay_corpus_for {
            return ExecutionMode::ReplayCorpus(ReplayCorpusOptions {
                replay_corpus_for,
                time_budget_type: options.time_budget_type,
                jobs: options.jobs,
            });
        }

        if options.replay_findings {
            return ExecutionMode::ReplayAllCrashes;
        }

        if let Some(replay_id) = &options.replay_id {
            return ExecutionMode::ReplayCrash(ReplayCrashOptions { replay_id: replay_id.clone() });
        }

        // Continuous fuzzing mode is selected if an explicit duration/budget (`fuzz_for`) is specified.
        if let Some(fuzz_for) = &options.fuzz_for {
            return ExecutionMode::Fuzz(FuzzOptions { fuzz_for: *fuzz_for, jobs: options.jobs });
        }

        ExecutionMode::SmokeTest
    }
}

/// Mode-specific options for continuous fuzzing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzOptions {
    pub fuzz_for: RunDuration,

    /// If `jobs` is `None`, we won't specify the number of jobs while invoking Centipede and it
    /// will use its own default value.
    pub jobs: Option<usize>,
}

/// The duration or limit for fuzzing or replaying corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunDuration {
    /// Run indefinitely until manually stopped or a crash is found.
    Indefinitely,

    /// Run for a specific fixed duration.
    Fixed(humantime::Duration),
}

impl FromStr for RunDuration {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        let s_lower = s.trim().to_lowercase();
        if s_lower == "inf" || s_lower == "infinity" {
            Ok(RunDuration::Indefinitely)
        } else {
            let duration: humantime::Duration = s
                .parse()
                .with_context(|| format!("while attempting to parse duration string '{s}'"))?;
            Ok(RunDuration::Fixed(duration))
        }
    }
}

impl Display for RunDuration {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            RunDuration::Indefinitely => write!(f, "inf"),
            RunDuration::Fixed(duration) => write!(f, "{duration}"),
        }
    }
}

/// Mode-specific options for replaying a specific crashing input from the corpus database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayCrashOptions {
    pub replay_id: String,
}

/// Mode-specific options for replaying corpus for a duration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayCorpusOptions {
    pub replay_corpus_for: RunDuration,
    pub time_budget_type: TimeBudgetType,
    /// If `jobs` is `None`, we won't specify the number of jobs while invoking Centipede and it
    /// will use its own default value.
    pub jobs: Option<usize>,
}

/// Mode-specific options for listing crash IDs from the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListCrashIdsOptions {
    pub list_crash_ids_file: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;
    use std::ffi::OsString;

    #[gtest]
    fn test_duration_from_str_inf() {
        let duration: RunDuration = "inf".parse().expect("failed to parse 'inf'");
        expect_that!(duration, eq(RunDuration::Indefinitely));
    }

    #[gtest]
    fn test_duration_from_str_infinity() {
        let duration: RunDuration = "infinity".parse().expect("failed to parse 'infinity'");
        expect_that!(duration, eq(RunDuration::Indefinitely));
    }

    #[gtest]
    fn test_duration_from_str_fixed() {
        let duration: RunDuration = "10s".parse().expect("failed to parse '10s'");
        let expected_fixed = humantime::Duration::from(std::time::Duration::from_secs(10));
        expect_that!(duration, eq(RunDuration::Fixed(expected_fixed)));
    }

    #[gtest]
    fn test_duration_from_str_invalid() {
        let result: Result<RunDuration, _> = "invalid_duration".parse();
        expect_true!(result.is_err());
    }

    #[gtest]
    fn test_duration_display() {
        expect_that!(RunDuration::Indefinitely.to_string(), eq("inf"));
        let fixed =
            RunDuration::Fixed(humantime::Duration::from(std::time::Duration::from_secs(10)));
        expect_that!(fixed.to_string(), eq("10s"));
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
    fn test_jobs_options_parsing_env() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_JOBS", "4");
        }

        let options = FuzzTestOptions::parse_from(std::iter::empty::<OsString>());

        expect_that!(options.jobs, eq(Some(4)));

        // Setting jobs alone should not enter fuzzing mode; it defaults to smoke test mode.
        expect_that!(ExecutionMode::from_fuzztest_options(&options), eq(&ExecutionMode::SmokeTest));

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_JOBS");
        }
    }

    #[gtest]
    fn test_jobs_with_fuzz_for_parsing_env() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_JOBS", "4");
            std::env::set_var("FUZZTEST_FUZZ_FOR", "5s");
        }

        let options = FuzzTestOptions::parse_from(std::iter::empty::<OsString>());

        expect_that!(options.jobs, eq(Some(4)));
        let expected_duration = "5s".parse().expect("valid duration");
        expect_that!(
            ExecutionMode::from_fuzztest_options(&options),
            eq(&ExecutionMode::Fuzz(FuzzOptions {
                fuzz_for: RunDuration::Fixed(expected_duration),
                jobs: Some(4),
            }))
        );

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_JOBS");
            std::env::remove_var("FUZZTEST_FUZZ_FOR");
        }
    }

    #[gtest]
    fn test_jobs_with_replay_corpus_parsing_env() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_JOBS", "4");
            std::env::set_var("FUZZTEST_REPLAY_CORPUS_FOR", "10s");
            std::env::set_var("FUZZTEST_CORPUS_DB", "/tmp/corpus_db");
        }

        let options = FuzzTestOptions::parse_from(std::iter::empty::<OsString>());

        expect_that!(options.jobs, eq(Some(4)));
        let expected_duration = "10s".parse().expect("valid duration string");
        expect_that!(
            ExecutionMode::from_fuzztest_options(&options),
            eq(&ExecutionMode::ReplayCorpus(ReplayCorpusOptions {
                replay_corpus_for: expected_duration,
                time_budget_type: TimeBudgetType::PerTest,
                jobs: Some(4),
            }))
        );

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_JOBS");
            std::env::remove_var("FUZZTEST_REPLAY_CORPUS_FOR");
            std::env::remove_var("FUZZTEST_CORPUS_DB");
        }
    }

    #[gtest]
    fn test_replay_findings_requires_corpus_db() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_REPLAY_FINDINGS", "true");
            std::env::remove_var("FUZZTEST_CORPUS_DB");
        }

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_REPLAY_FINDINGS");
        }

        let err = result.expect_err("parsing should fail when corpus_db is missing");
        expect_that!(err.kind(), eq(clap::error::ErrorKind::MissingRequiredArgument));
    }

    #[gtest]
    fn test_replay_findings_with_corpus_db_succeeds() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_REPLAY_FINDINGS", "true");
            std::env::set_var("FUZZTEST_CORPUS_DB", "/tmp/corpus_db");
        }

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_REPLAY_FINDINGS");
            std::env::remove_var("FUZZTEST_CORPUS_DB");
        }

        let options = result
            .expect("parsing should succeed when both replay_findings and corpus_db are present");
        expect_that!(options.replay_findings, eq(true));
        expect_that!(options.corpus_db.as_deref(), eq(Some("/tmp/corpus_db")));
    }

    #[gtest]
    fn test_replay_corpus_for_requires_corpus_db() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_REPLAY_CORPUS_FOR", "10s");
            std::env::remove_var("FUZZTEST_CORPUS_DB");
        }

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_REPLAY_CORPUS_FOR");
        }

        let err = result.expect_err("parsing should fail when corpus_db is missing");
        expect_that!(err.kind(), eq(clap::error::ErrorKind::MissingRequiredArgument));
    }

    #[gtest]
    fn test_replay_corpus_for_with_corpus_db_succeeds() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_REPLAY_CORPUS_FOR", "10s");
            std::env::set_var("FUZZTEST_CORPUS_DB", "/tmp/corpus_db");
        }

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_REPLAY_CORPUS_FOR");
            std::env::remove_var("FUZZTEST_CORPUS_DB");
        }

        let options = result
            .expect("parsing should succeed when both replay_corpus_for and corpus_db are present");
        expect_that!(
            options.replay_corpus_for,
            eq(Some("10s".parse().expect("valid duration string")))
        );
        expect_that!(options.corpus_db.as_deref(), eq(Some("/tmp/corpus_db")));
        expect_that!(options.time_budget_type, eq(TimeBudgetType::PerTest));
    }

    #[gtest]
    fn test_replay_corpus_for_inf_env_succeeds() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_REPLAY_CORPUS_FOR", "inf");
            std::env::set_var("FUZZTEST_CORPUS_DB", "/tmp/corpus_db");
        }

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_REPLAY_CORPUS_FOR");
            std::env::remove_var("FUZZTEST_CORPUS_DB");
        }

        let options = result.expect(
            "parsing should succeed when replay_corpus_for is inf and corpus_db is present",
        );
        expect_that!(options.replay_corpus_for, eq(Some(RunDuration::Indefinitely)));
        expect_that!(options.corpus_db.as_deref(), eq(Some("/tmp/corpus_db")));
    }

    #[gtest]
    fn test_replay_corpus_for_infinity_env_succeeds() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_REPLAY_CORPUS_FOR", "infinity");
            std::env::set_var("FUZZTEST_CORPUS_DB", "/tmp/corpus_db");
        }

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_REPLAY_CORPUS_FOR");
            std::env::remove_var("FUZZTEST_CORPUS_DB");
        }

        let options = result.expect(
            "parsing should succeed when replay_corpus_for is infinity and corpus_db is present",
        );
        expect_that!(options.replay_corpus_for, eq(Some(RunDuration::Indefinitely)));
        expect_that!(options.corpus_db.as_deref(), eq(Some("/tmp/corpus_db")));
    }

    #[gtest]
    fn test_replay_corpus_for_with_total_time_budget() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_REPLAY_CORPUS_FOR", "10s");
            std::env::set_var("FUZZTEST_TIME_BUDGET_TYPE", "total");
            std::env::set_var("FUZZTEST_CORPUS_DB", "/tmp/corpus_db");
        }

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_REPLAY_CORPUS_FOR");
            std::env::remove_var("FUZZTEST_TIME_BUDGET_TYPE");
            std::env::remove_var("FUZZTEST_CORPUS_DB");
        }

        let options = result.expect("parsing should succeed with total time budget type");
        expect_that!(
            options.replay_corpus_for,
            eq(Some("10s".parse().expect("valid duration string")))
        );
        expect_that!(options.corpus_db.as_deref(), eq(Some("/tmp/corpus_db")));
        expect_that!(options.time_budget_type, eq(TimeBudgetType::Total));
    }

    #[gtest]
    fn test_replay_corpus_for_inf_with_total_time_budget() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_REPLAY_CORPUS_FOR", "inf");
            std::env::set_var("FUZZTEST_TIME_BUDGET_TYPE", "total");
            std::env::set_var("FUZZTEST_CORPUS_DB", "/tmp/corpus_db");
        }

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_REPLAY_CORPUS_FOR");
            std::env::remove_var("FUZZTEST_TIME_BUDGET_TYPE");
            std::env::remove_var("FUZZTEST_CORPUS_DB");
        }

        let options = result.expect("parsing should succeed with total time budget type and inf");
        expect_that!(options.replay_corpus_for, eq(Some(RunDuration::Indefinitely)));
        expect_that!(options.corpus_db.as_deref(), eq(Some("/tmp/corpus_db")));
        expect_that!(options.time_budget_type, eq(TimeBudgetType::Total));
    }

    #[gtest]
    fn test_list_crash_ids_requires_corpus_db() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_LIST_CRASH_IDS", "true");
            std::env::set_var("FUZZTEST_LIST_CRASH_IDS_FILE", "/tmp/crashes.txt");
            std::env::remove_var("FUZZTEST_CORPUS_DB");
        }

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_LIST_CRASH_IDS");
            std::env::remove_var("FUZZTEST_LIST_CRASH_IDS_FILE");
        }

        let err = result.expect_err("parsing should fail when corpus_db is missing");
        expect_that!(err.kind(), eq(clap::error::ErrorKind::MissingRequiredArgument));
    }

    #[gtest]
    fn test_list_crash_ids_requires_list_crash_ids_file() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_LIST_CRASH_IDS", "true");
            std::env::set_var("FUZZTEST_CORPUS_DB", "/tmp/corpus_db");
            std::env::remove_var("FUZZTEST_LIST_CRASH_IDS_FILE");
        }

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_LIST_CRASH_IDS");
            std::env::remove_var("FUZZTEST_CORPUS_DB");
        }

        let err = result.expect_err("parsing should fail when list_crash_ids_file is missing");
        expect_that!(err.kind(), eq(clap::error::ErrorKind::MissingRequiredArgument));
    }

    #[gtest]
    fn test_list_crash_ids_file_requires_list_crash_ids() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_LIST_CRASH_IDS_FILE", "/tmp/crashes.txt");
            std::env::set_var("FUZZTEST_CORPUS_DB", "/tmp/corpus_db");
            std::env::remove_var("FUZZTEST_LIST_CRASH_IDS");
        }

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_LIST_CRASH_IDS_FILE");
            std::env::remove_var("FUZZTEST_CORPUS_DB");
        }

        let err = result.expect_err("parsing should fail when list_crash_ids is missing");
        expect_that!(err.kind(), eq(clap::error::ErrorKind::MissingRequiredArgument));
    }

    #[gtest]
    fn test_list_crash_ids_with_corpus_db_and_file_succeeds() {
        // SAFETY: Testing environment parsing in single-threaded context.
        unsafe {
            std::env::set_var("FUZZTEST_LIST_CRASH_IDS", "true");
            std::env::set_var("FUZZTEST_LIST_CRASH_IDS_FILE", "/tmp/crashes.txt");
            std::env::set_var("FUZZTEST_CORPUS_DB", "/tmp/corpus_db");
        }

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        // SAFETY: Cleaning up environment variables.
        unsafe {
            std::env::remove_var("FUZZTEST_LIST_CRASH_IDS");
            std::env::remove_var("FUZZTEST_LIST_CRASH_IDS_FILE");
            std::env::remove_var("FUZZTEST_CORPUS_DB");
        }

        let options = result.expect(
            "parsing should succeed when list_crash_ids, list_crash_ids_file, and corpus_db are present",
        );
        expect_that!(options.list_crash_ids, eq(true));
        expect_that!(options.list_crash_ids_file.as_deref(), eq(Some("/tmp/crashes.txt")));
        expect_that!(options.corpus_db.as_deref(), eq(Some("/tmp/corpus_db")));

        let mode = ExecutionMode::from_fuzztest_options(&options);
        expect_that!(
            mode,
            eq(&ExecutionMode::ListCrashIds(ListCrashIdsOptions {
                list_crash_ids_file: "/tmp/crashes.txt".to_string()
            }))
        );
    }
}
