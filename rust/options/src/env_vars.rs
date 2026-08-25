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

//! Testing utilities for safely modifying environment variables in
//! single-threaded tests.
//!
//! # Safety & Limitations
//! Modifying process environment variables (`std::env::set_var` /
//! `std::env::remove_var`) is inherently `unsafe` because it affects the
//! global process environment.
//!
//! The functions [`with_env_var`] and [`with_env_vars`] use the scoped closure
//! RAII pattern: they apply modifications for the duration of a closure and
//! restore original environment variables in reverse order when the closure
//! finishes or panics.
//!
//! Callers must ensure that tests run single-threaded (which can be
//! validated via [`assert_single_threaded_test_environment`]) and that no
//! other threads concurrently access the environment during execution.

use std::env;
use std::ffi::{OsStr, OsString};

/// Asserts that the test process is executing in single-threaded mode.
///
/// Verifies that at least one single-threaded test harness indicator
/// (`RUST_TEST_THREADS=1` or `--test-threads=1`) is present and that no
/// conflicting multi-threaded settings exist.
///
/// # Panics
/// Panics if called outside a single-threaded test environment or if
/// conflicting/multi-threaded thread settings are detected.
pub fn assert_single_threaded_test_environment() {
    let mut has_single_threaded_indicator = false;

    if let Ok(val) = env::var("RUST_TEST_THREADS") {
        if val.trim() == "1" {
            has_single_threaded_indicator = true;
        } else {
            panic!(
                "EnvVars detected multi-threaded setting \
                 RUST_TEST_THREADS={val:?}. Single-threaded execution is \
                 required to prevent environment data races."
            );
        }
    }

    let args: Vec<String> = env::args().collect();
    let mut i = 0;
    while i < args.len() {
        let arg = &args[i];

        if let Some(val) = arg.strip_prefix("--test-threads=") {
            if val == "1" {
                has_single_threaded_indicator = true;
            } else {
                panic!(
                    "EnvVars detected multi-threaded argument \
                     --test-threads={val}. Single-threaded execution is \
                     required to prevent environment data races."
                );
            }
        } else if arg == "--test-threads" {
            if i + 1 < args.len() {
                let val = &args[i + 1];
                if val == "1" {
                    has_single_threaded_indicator = true;
                    i += 1;
                } else {
                    panic!(
                        "EnvVars detected multi-threaded argument \
                         --test-threads {val}. Single-threaded execution is \
                         required to prevent environment data races."
                    );
                }
            } else {
                panic!("EnvVars detected incomplete argument --test-threads.");
            }
        }

        i += 1;
    }

    if !has_single_threaded_indicator {
        panic!(
            "Environment modification tests can only be run single-threaded \
             (e.g., --test-threads=1 or RUST_TEST_THREADS=1) to prevent \
             environment data races."
        );
    }
}

/// Executes a closure with a temporary environment variable modification.
///
/// Restores the original environment variable value when the closure
/// completes or panics.
///
/// # Safety
/// The caller must ensure that no other threads are concurrently reading or
/// writing environment variables during the execution of `f`.
pub unsafe fn with_env_var<K, V, R, F>(key: K, val: V, f: F) -> R
where
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
    F: FnOnce() -> R,
{
    // SAFETY: Forwarded to with_env_vars.
    unsafe { with_env_vars([(key.as_ref(), Some(val.as_ref()))], f) }
}

/// Executes a closure with multiple temporary environment variable
/// modifications.
///
/// For each entry `(key, value)`:
/// - If `value` is `Some(v)`, the environment variable `key` is set to `v`.
/// - If `value` is `None`, the environment variable `key` is unset.
///
/// Restores all original environment variable values in reverse order when the
/// closure completes or panics.
///
/// # Safety
/// The caller must ensure that no other threads are concurrently reading or
/// writing environment variables during the execution of `f`.
pub unsafe fn with_env_vars<K, V, I, R, F>(vars: I, f: F) -> R
where
    K: AsRef<OsStr>,
    V: AsRef<OsStr>,
    I: IntoIterator<Item = (K, Option<V>)>,
    F: FnOnce() -> R,
{
    struct EnvRestorer {
        saved_vars: Vec<(OsString, Option<OsString>)>,
    }

    impl Drop for EnvRestorer {
        fn drop(&mut self) {
            // Restore in reverse order of modification to handle repeated
            // keys correctly.
            for (key, original_val) in self.saved_vars.iter().rev() {
                // SAFETY: Restoring original environment values within the
                // caller's unsafe scope.
                unsafe {
                    match original_val {
                        Some(val) => env::set_var(key, val),
                        None => env::remove_var(key),
                    }
                }
            }
        }
    }

    let mut restorer = EnvRestorer { saved_vars: Vec::new() };

    for (key, val) in vars {
        let key_ref = key.as_ref();
        let key_os = key_ref.to_os_string();
        let original_val = env::var_os(key_ref);
        restorer.saved_vars.push((key_os, original_val));

        // SAFETY: Upheld by caller contract.
        unsafe {
            match val {
                Some(v) => env::set_var(key_ref, v.as_ref()),
                None => env::remove_var(key_ref),
            }
        }
    }

    f()
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;
    use std::panic;

    #[gtest]
    fn test_with_env_var_sets_and_restores() {
        const KEY: &str = "FUZZTEST_TEST_SCOPED_ENV_VAR";
        assert_single_threaded_test_environment();

        // Ensure initially unset
        // SAFETY: Test runs in verified single-threaded context.
        unsafe {
            env::remove_var(KEY);
        }

        // SAFETY: Verified single-threaded execution and no concurrent
        // threads.
        let value_during_scope = unsafe { with_env_var(KEY, "scoped_val", || env::var(KEY)) };

        expect_that!(value_during_scope, ok(eq("scoped_val")));
        expect_true!(env::var(KEY).is_err());
    }

    #[gtest]
    fn test_with_env_vars_multiple_and_reverse_order_restoration() {
        const KEY1: &str = "FUZZTEST_TEST_KEY1";
        const KEY2: &str = "FUZZTEST_TEST_KEY2";
        assert_single_threaded_test_environment();

        // Setup pre-existing state
        // SAFETY: Test runs in verified single-threaded context.
        unsafe {
            env::set_var(KEY1, "init1");
            env::set_var(KEY2, "init2");
        }

        // Modify KEY1 twice and unset KEY2
        // SAFETY: Verified single-threaded execution and no concurrent
        // threads.
        let (val1_during_scope, val2_during_scope) = unsafe {
            with_env_vars(
                [(KEY1, Some("intermediate")), (KEY1, Some("final")), (KEY2, None)],
                || (env::var(KEY1), env::var(KEY2)),
            )
        };

        expect_that!(val1_during_scope, ok(eq("final")));
        expect_true!(val2_during_scope.is_err());

        // Original values must be restored in reverse order
        expect_that!(env::var(KEY1), ok(eq("init1")));
        expect_that!(env::var(KEY2), ok(eq("init2")));

        // Cleanup
        // SAFETY: Test runs in verified single-threaded context.
        unsafe {
            env::remove_var(KEY1);
            env::remove_var(KEY2);
        }
    }

    #[gtest]
    fn test_with_env_vars_restores_on_panic() {
        const KEY: &str = "FUZZTEST_TEST_PANIC_RECOVERY";
        assert_single_threaded_test_environment();

        // SAFETY: Test runs in verified single-threaded context.
        unsafe {
            env::set_var(KEY, "before_panic");
        }

        let panic_result = panic::catch_unwind(|| {
            // SAFETY: Verified single-threaded execution and no concurrent
            // threads.
            unsafe {
                with_env_var(KEY, "during_panic", || {
                    panic!("simulated test failure");
                });
            }
        });

        expect_true!(panic_result.is_err());
        // Environment must be restored despite the panic
        expect_that!(env::var(KEY), ok(eq("before_panic")));

        // Cleanup
        // SAFETY: Test runs in verified single-threaded context.
        unsafe {
            env::remove_var(KEY);
        }
    }
}
