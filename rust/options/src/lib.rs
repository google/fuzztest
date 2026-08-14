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

// This module provides the core command-line flag and environment variable options
// structure (`FuzzTestOptions`) and domain execution modes (`ExecutionMode`).

use clap::{Parser, ValueEnum};
use humantime::Duration;
use std::collections::HashMap;
use std::ffi::{OsStr, OsString};
use std::sync::{Mutex, MutexGuard};

/// Time budget calculation type for replay corpus mode.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TimeBudgetType {
    #[default]
    PerTest,
    Total,
}

/// Parses a fuzzing duration string from `FUZZTEST_FUZZ_FOR`.
///
/// Matches `"inf"` or `"infinity"` to [`FuzzFor::Indefinitely`]. All other values
/// are parsed as standard human-readable durations (for example, `"5s"` or `"10m"`).
fn parse_fuzz_for(s: &str) -> anyhow::Result<FuzzFor> {
    let s_lower = s.trim().to_lowercase();
    if s_lower == "inf" || s_lower == "infinity" {
        Ok(FuzzFor::Indefinitely)
    } else {
        let duration = s.parse()?;
        Ok(FuzzFor::Duration(duration))
    }
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
    #[arg(env = "FUZZTEST_FUZZ_FOR", long, value_parser = parse_fuzz_for)]
    pub fuzz_for: Option<FuzzFor>,

    /// If true, subprocess logs are printed after every batch. Note that crash logs are always
    /// printed regardless of this flag's value.
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

impl ExecutionMode {
    /// Evaluates the raw options and maps them to a strongly-typed domain `ExecutionMode`.
    ///
    /// This decouples raw environment/CLI option parsing from execution mode validation.
    pub fn from_fuzztest_options(options: &FuzzTestOptions) -> ExecutionMode {
        if let Some(replay_corpus_for) = options.replay_corpus_for {
            return ExecutionMode::ReplayCorpus(ReplayCorpusOptions {
                replay_corpus_for,
                time_budget_type: options.time_budget_type,
            });
        }

        if options.replay_findings {
            return ExecutionMode::ReplayAllCrashes;
        }

        if let Some(replay_id) = &options.replay_id {
            return ExecutionMode::ReplayCrash(ReplayCrashOptions { replay_id: replay_id.clone() });
        }

        if let Some(fuzz_for) = options.fuzz_for {
            return ExecutionMode::Fuzz(FuzzOptions { fuzz_for, jobs: options.jobs.clone() });
        }

        ExecutionMode::SmokeTest
    }
}

/// Mode-specific options for continuous fuzzing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzOptions {
    pub fuzz_for: FuzzFor,

    /// If `jobs` is `None`, we won't specify the number of jobs while invoking Centipede and it
    /// will use its own default value.
    pub jobs: Option<usize>,
}

/// The duration or limit for fuzzing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FuzzFor {
    /// Fuzz indefinitely until it is manually stopped or a crash is found.
    Indefinitely,

    /// Fuzz for a specific duration.
    Duration(Duration),
}

/// Mode-specific options for replaying a specific crashing input from the corpus database.
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

static ENV_MUTEX: Mutex<()> = Mutex::new(());

/// Builder for safely setting and unsetting environment variables under a global lock in tests.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct EnvVars {
    modifications: HashMap<OsString, Option<OsString>>,
}

impl EnvVars {
    /// Creates a new empty `EnvVars` builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Specifies an environment variable to set. Overwrites any previous modification for `key`.
    pub fn set(mut self, key: impl AsRef<OsStr>, val: impl AsRef<OsStr>) -> Self {
        self.modifications.insert(key.as_ref().to_os_string(), Some(val.as_ref().to_os_string()));
        self
    }

    /// Specifies an environment variable to unset. Overwrites any previous modification for `key`.
    pub fn unset(mut self, key: impl AsRef<OsStr>) -> Self {
        self.modifications.insert(key.as_ref().to_os_string(), None);
        self
    }

    /// Locks the global environment mutex, records the original values of all modified variables,
    /// applies the requested modifications, and returns an `EnvVarGuard` that restores original values
    /// and unlocks the mutex when dropped.
    pub fn lock(self) -> EnvVarGuard<'static> {
        let guard = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
        self.lock_with(guard)
    }

    /// Applies environment variable modifications using an already acquired mutex guard.
    pub fn lock_with<'a>(self, guard: MutexGuard<'a, ()>) -> EnvVarGuard<'a> {
        let mut original_values = Vec::new();

        for (key, target_state) in self.modifications {
            original_values.push((key.clone(), std::env::var_os(&key)));
            // SAFETY: Access to environment variables is serialized by holding the global mutex guard.
            unsafe {
                match target_state {
                    Some(val) => std::env::set_var(&key, val),
                    None => std::env::remove_var(&key),
                }
            }
        }

        EnvVarGuard { _guard: guard, original_values }
    }
}

/// Guard managing modified environment variables. Restores original values when dropped.
#[must_use]
pub struct EnvVarGuard<'a> {
    _guard: MutexGuard<'a, ()>,
    original_values: Vec<(OsString, Option<OsString>)>,
}

impl<'a> Drop for EnvVarGuard<'a> {
    fn drop(&mut self) {
        for (key, orig) in &self.original_values {
            // SAFETY: Access to environment variables is serialized by the global mutex held in self._guard.
            unsafe {
                match orig {
                    Some(val) => std::env::set_var(key, val),
                    None => std::env::remove_var(key),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;
    use std::ffi::OsString;

    #[gtest]
    fn test_replay_id_requires_corpus_db() {
        let _guard = EnvVars::new()
            .set("FUZZTEST_REPLAY_ID", "my_crash_123")
            .unset("FUZZTEST_CORPUS_DB")
            .lock();

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        let err = result.expect_err("parsing should fail when corpus_db is missing");
        expect_that!(err.kind(), eq(clap::error::ErrorKind::MissingRequiredArgument));
    }

    #[gtest]
    fn test_replay_id_with_corpus_db_succeeds() {
        let _guard = EnvVars::new()
            .set("FUZZTEST_REPLAY_ID", "my_crash_123")
            .set("FUZZTEST_CORPUS_DB", "/tmp/corpus_db")
            .lock();

        let result = FuzzTestOptions::try_parse_from(std::iter::empty::<OsString>());

        let options =
            result.expect("parsing should succeed when both replay_id and corpus_db are present");
        expect_that!(options.replay_id.as_deref(), eq(Some("my_crash_123")));
        expect_that!(options.corpus_db.as_deref(), eq(Some("/tmp/corpus_db")));
    }

    #[gtest]
    fn test_modify_env_vars_restores_original_state() {
        const PREEXISTING_KEY: &str = "FUZZTEST_TEST_VAR_PREEXISTING";
        const NEW_KEY: &str = "FUZZTEST_TEST_VAR_NEW";
        const UNSET_KEY: &str = "FUZZTEST_TEST_VAR_UNSET";

        // Acquire global lock for the whole test duration so setup and cleanup are thread-safe.
        let lock = ENV_MUTEX.lock().unwrap_or_else(|e| e.into_inner());

        // Setup pre-existing state under lock
        unsafe {
            std::env::set_var(PREEXISTING_KEY, "initial_value");
            std::env::set_var(UNSET_KEY, "value_to_be_unset");
            std::env::remove_var(NEW_KEY);
        }

        {
            let _guard = EnvVars::new()
                .set(PREEXISTING_KEY, "modified_value")
                .set(NEW_KEY, "created_value")
                .unset(UNSET_KEY)
                .lock_with(lock);

            expect_that!(std::env::var(PREEXISTING_KEY), ok(eq("modified_value")));
            expect_that!(std::env::var(NEW_KEY), ok(eq("created_value")));
            expect_true!(std::env::var(UNSET_KEY).is_err());
        }

        // After guard drop, original state should be restored
        expect_that!(std::env::var(PREEXISTING_KEY), ok(eq("initial_value")));
        expect_true!(std::env::var(NEW_KEY).is_err());
        expect_that!(std::env::var(UNSET_KEY), ok(eq("value_to_be_unset")));

        // Cleanup
        unsafe {
            std::env::remove_var(PREEXISTING_KEY);
            std::env::remove_var(UNSET_KEY);
        }
    }

    #[gtest]
    fn test_env_vars_conflicting_modifications() {
        const KEY: &str = "FUZZTEST_TEST_VAR_CONFLICT";

        // Last modification wins: .set("val1").set("val2").unset() -> variable is unset
        {
            let _guard = EnvVars::new().set(KEY, "val1").set(KEY, "val2").unset(KEY).lock();

            expect_true!(std::env::var(KEY).is_err());
        }

        // Last modification wins: .unset().set("final_val") -> variable is "final_val"
        {
            let _guard = EnvVars::new().unset(KEY).set(KEY, "final_val").lock();

            expect_that!(std::env::var(KEY), ok(eq("final_val")));
        }

        expect_true!(std::env::var(KEY).is_err());
    }
}
