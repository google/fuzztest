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

//! Runs a fuzz test: as a worker of the FuzzTest engine, as its controller, or as a smoke test.
//!
//! The FFI with the engine lives in the `engine` crate. This module implements the traits of
//! that crate for a fuzz test, and needs no `unsafe` code.

#![forbid(unsafe_code)]

use super::domains::{GenericCorpusValue, GenericDomain};
use super::internal::{BoxedFuzzTest, FuzzTest};
use super::options::{self, CentipedeArgs, ExecutionAction};
use ::engine::{
    Adapter, AdapterManager, CoverageDomainRegistry, ExecuteContext, FeedbackSink, RunOutcome,
};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::Path;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::time::Instant;

/// Drives one [`FuzzTest`] instance for the fuzzing engine.
pub struct RustFuzzTestAdapter {
    fuzz_test: BoxedFuzzTest,
}

impl RustFuzzTestAdapter {
    /// Runs `f` with the domains of the fuzz test locked.
    ///
    /// The lock is released before this returns, so callers never hold it while they call back
    /// into the engine.
    fn with_domains<R>(&self, f: impl FnOnce(&mut dyn GenericDomain) -> R) -> R {
        let domains = self.fuzz_test.domains();
        // The lock is only poisoned if a `Domain` method panicked while holding it. In worker
        // mode that panic already aborted the process, because it unwound into an `extern "C"`
        // callback.
        let mut guard = domains.lock().expect("a Domain method panicked while holding the lock");
        f(&mut *guard)
    }
}

impl Adapter for RustFuzzTestAdapter {
    type Input = GenericCorpusValue;
    // Reported to the engine in its `Debug` format, which for `anyhow::Error` is the message
    // followed by the chain of causes.
    type Error = anyhow::Error;

    fn set_up_coverage_domains(&self, registry: &CoverageDomainRegistry) {
        registry.set_up_sancov_domains();
    }

    fn random_seed_input(&self) -> anyhow::Result<GenericCorpusValue> {
        self.with_domains(|domains| domains.init(&mut rand::rng()))
    }

    fn mutate(
        &self,
        origin: &GenericCorpusValue,
        shrink: bool,
    ) -> anyhow::Result<GenericCorpusValue> {
        let mut mutant = origin.clone();
        self.with_domains(|domains| domains.mutate(&mut mutant, &mut rand::rng(), shrink))?;
        Ok(mutant)
    }

    fn execute(
        &self,
        cx: &ExecuteContext<'_>,
        input: &GenericCorpusValue,
        feedback: &FeedbackSink,
    ) {
        // TODO(the-shank): modify this in order to support persistent mode and batch execution.
        static CLEAR_STARTUP_COVERAGE: AtomicBool = AtomicBool::new(true);
        // Called even in unguided mode: besides clearing coverage, this frees the SanCov state of
        // threads that exited during the previous execution, which would otherwise accumulate.
        coverage::prepare_coverage(CLEAR_STARTUP_COVERAGE.swap(false, Ordering::AcqRel));

        let result = self.fuzz_test.execute(input);

        if !options::get_fuzztest_options().unguided {
            coverage::post_process_coverage(false);
            feedback.emit_sancov_features();
        }

        if !result {
            // TODO(the-shank): the signature should be different for different panics. Currently,
            // all test failures due to panics are reported with the same signature.
            cx.emit_finding("Property function ran but crashed.", "Unwinding panic");
        }
    }

    fn serialize_input(&self, input: &GenericCorpusValue) -> anyhow::Result<Vec<u8>> {
        self.with_domains(|domains| domains.serialize_corpus(input))
    }

    fn deserialize_input(&self, content: &[u8]) -> anyhow::Result<GenericCorpusValue> {
        self.with_domains(|domains| domains.parse_corpus(content))
    }
}

/// Identifies a registered fuzz test and constructs its [`FuzzTest`] instances.
pub struct RustFuzzTestAdapterManager {
    /// Rust module-qualified name of the fuzz test.
    pub test_name: &'static str,
    /// Factory that constructs a fresh [`BoxedFuzzTest`] for the test.
    pub fuzz_test_factory: fn() -> BoxedFuzzTest,
}

impl RustFuzzTestAdapterManager {
    /// Constructs a new [`BoxedFuzzTest`] instance for this test.
    pub fn construct_fuzz_test(&self) -> BoxedFuzzTest {
        (self.fuzz_test_factory)()
    }
}

fn binary_id_from_arg(argv0: Option<OsString>) -> Vec<u8> {
    let argv0 = argv0.unwrap_or_default();
    let file_name = Path::new(&argv0).file_name().unwrap_or_default();
    file_name.as_encoded_bytes().to_vec()
}

impl AdapterManager for RustFuzzTestAdapterManager {
    type Adapter = RustFuzzTestAdapter;

    fn binary_id(&self) -> Vec<u8> {
        // The engine asks for the binary ID at most once per process, so nothing is cached. A
        // missing `argv[0]` yields an empty ID and a non-UTF-8 one is emitted as is: this runs
        // inside an `extern "C"` callback and must not panic.
        binary_id_from_arg(env::args_os().next())
    }

    // Replaces "::" with "." to avoid parsing issues in Centipede. Centipede uses ":" as a
    // separator in CENTIPEDE_RUNNER_FLAGS and its parser replaces all ":" with "\0", which would
    // truncate Rust paths.
    fn test_name(&self) -> String {
        self.test_name.replace("::", ".")
    }

    fn construct_adapter(&self) -> RustFuzzTestAdapter {
        RustFuzzTestAdapter { fuzz_test: self.construct_fuzz_test() }
    }
}

/// Runs `fuzztest` locally with random mutations for a short fixed duration.
///
/// # Panics
///
/// Panics if locking, initializing, or mutating the test domains fails, or if the property
/// function fails on a generated input.
pub fn run_smoke_test(fuzztest: &dyn FuzzTest) {
    // TODO(the-shank): these should be configurable externally.
    const SMOKE_TEST_DURATION: Duration = Duration::from_secs(1);
    const ONLY_SHRINK: bool = false;

    let deadline = Instant::now() + SMOKE_TEST_DURATION;
    let domains = fuzztest.domains();
    // TODO(the-shank): the rng seed should be configurable
    let mut rng = rand::rng();

    let mut corpus_value = domains
        .lock()
        .expect("Failed to lock domains")
        .init(&mut rng)
        .expect("domain initialization should succeed to provide an initial corpus value");
    loop {
        // DISCUSS: probably need a more "googletest" approach to handling the result here?
        assert!(
            fuzztest.execute(&corpus_value),
            "the property function failed; see the counterexample reported above"
        );
        if Instant::now() >= deadline {
            break;
        }
        domains
            .lock()
            .expect("Failed to lock domains")
            .mutate(&mut corpus_value, &mut rng, ONLY_SHRINK)
            .expect("domain mutation should succeed");
    }
}

/// Processes and executes a fuzz test using the provided [`RustFuzzTestAdapterManager`].
///
/// This function serves as the primary entry point for running a fuzz test:
///
/// 1. Worker mode: registers the sanitizer crash handler and offers the test to the fuzzing engine
///    (e.g., Centipede) via [`engine::run_worker_if_requested`].
///    - If the binary was spawned as a worker process by the fuzzing engine, control remains in the
///      engine loop until it completes.
///    - Returns cleanly on [`RunOutcome::Success`], so that the harness continues with the next
///      test, and exits the process with status 1 on [`RunOutcome::Failure`].
/// 2. Otherwise, the action selected by the FuzzTest options: run the fuzzing controller
///    (standalone fuzzing or crash replay), or fall back to a short local smoke test, as in
///    standard `blaze test` or `cargo test` runs.
///
/// # Panics
///
/// Panics if the controller reports a failure in standalone mode, or if the smoke test finds a
/// failing input.
pub fn process(manager: RustFuzzTestAdapterManager) {
    super::crash_handler::register_crash_handler();

    match ::engine::run_worker_if_requested(&manager) {
        // The harness continues with the next test.
        Some(RunOutcome::Success) => return,
        Some(RunOutcome::Failure) => process::exit(1),
        // Worker mode was not requested.
        None => {}
    }

    match options::determine_execution_action(manager.test_name) {
        ExecutionAction::Standalone(args) => run_controller(&manager, args),
        ExecutionAction::ReplayAllCrashes { args, list_file } => {
            run_controller(&manager, args);
            replay_listed_crashes(&manager, list_file.path());
        }
        ExecutionAction::SmokeTest => {
            let fuzz_test = manager.construct_fuzz_test();
            run_smoke_test(fuzz_test.as_ref());
        }
    }
}

/// Runs the controller and panics if it reports a failure, which fails the test in the harness.
fn run_controller(manager: &RustFuzzTestAdapterManager, args: CentipedeArgs) {
    if ::engine::run_controller(manager, &args.to_byte_slices()) == RunOutcome::Failure {
        panic!("FuzzTest controller reported failure");
    }
}

/// Replays every crash listed in `list_file`, with one controller run per crash ID.
///
/// A list that cannot be read and a replay that cannot be prepared are reported as warnings.
/// They do not fail the test, in the same way that a crash that reproduces does not: this mode
/// replays as much as it can.
fn replay_listed_crashes(manager: &RustFuzzTestAdapterManager, list_file: &Path) {
    let crash_ids = match fs::read_to_string(list_file) {
        Ok(crash_ids) => crash_ids,
        Err(e) => {
            eprintln!(
                "warning: no crash was replayed, cannot read the crash list {}: {e}",
                list_file.display()
            );
            return;
        }
    };
    let options = options::get_fuzztest_options();
    for crash_id in crash_ids.lines().map(str::trim).filter(|crash_id| !crash_id.is_empty()) {
        let replay_mode = options::ExecutionMode::ReplayCrash(options::ReplayCrashOptions {
            replay_id: crash_id.to_string(),
        });
        match CentipedeArgs::from_execution_mode(&replay_mode, options, manager.test_name, None) {
            Ok(Some(replay_args)) => {
                // The outcome is ignored: replaying a crash is expected to report a failure, and
                // the remaining crashes should still be replayed.
                let _ = ::engine::run_controller(manager, &replay_args.to_byte_slices());
            }
            Ok(None) => {
                eprintln!("warning: crash {crash_id} was not replayed: nothing to run for it")
            }
            Err(e) => eprintln!("warning: crash {crash_id} was not replayed: {e:#}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;
    use rand::Rng;
    #[cfg(unix)]
    use std::os::unix::ffi::OsStringExt;
    use std::sync::{Arc, Mutex};
    use tempfile::TempDir;

    struct FakeDomain;

    impl GenericDomain for FakeDomain {
        fn init(&mut self, _rng: &mut dyn Rng) -> anyhow::Result<GenericCorpusValue> {
            Ok(Box::new(()))
        }

        fn mutate(
            &mut self,
            _corpus_value: &mut GenericCorpusValue,
            _rng: &mut dyn Rng,
            _only_shrink: bool,
        ) -> anyhow::Result<()> {
            Ok(())
        }

        fn parse_corpus(&self, _data: &[u8]) -> anyhow::Result<GenericCorpusValue> {
            Ok(Box::new(()))
        }

        fn serialize_corpus(&self, _val: &GenericCorpusValue) -> anyhow::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    struct FakeFuzzTest {
        succeeds: bool,
    }

    impl FuzzTest for FakeFuzzTest {
        fn name(&self) -> &'static str {
            "fake_test"
        }

        fn activate(&mut self) {}

        fn mutate(&mut self) {}

        fn execute(&self, _args: &GenericCorpusValue) -> bool {
            self.succeeds
        }

        fn domains(&self) -> Arc<Mutex<dyn GenericDomain>> {
            Arc::new(Mutex::new(FakeDomain))
        }
    }

    fn make_succeeding_test() -> BoxedFuzzTest {
        Box::new(FakeFuzzTest { succeeds: true })
    }

    #[gtest]
    fn binary_id_from_arg_strips_directory_and_handles_missing_or_empty() {
        expect_eq!(binary_id_from_arg(Some("/usr/local/bin/my_fuzzer".into())), b"my_fuzzer");
        expect_eq!(binary_id_from_arg(None), b"");
        expect_eq!(binary_id_from_arg(Some("".into())), b"");
    }

    #[cfg(unix)]
    #[gtest]
    fn binary_id_from_arg_preserves_non_utf8_bytes() {
        let arg = OsString::from_vec(b"/tmp/fuzz_\xff_bin".to_vec());
        expect_eq!(binary_id_from_arg(Some(arg)), b"fuzz_\xff_bin");
    }

    #[gtest]
    fn adapter_manager_replaces_double_colons_in_test_name() {
        let manager = RustFuzzTestAdapterManager {
            test_name: "crate::sub::prop",
            fuzz_test_factory: make_succeeding_test,
        };
        expect_eq!(manager.test_name(), "crate.sub.prop");
    }

    #[gtest]
    fn replay_listed_crashes_ignores_missing_list_file() -> Result<()> {
        let dir = TempDir::new()?;
        let missing = dir.path().join("missing_crashes.txt");
        let manager = RustFuzzTestAdapterManager {
            test_name: "crate::sub::prop",
            fuzz_test_factory: make_succeeding_test,
        };

        replay_listed_crashes(&manager, &missing);
        Ok(())
    }

    #[gtest]
    fn run_smoke_test_succeeds_when_property_holds() {
        run_smoke_test(&FakeFuzzTest { succeeds: true });
    }

    #[gtest]
    #[should_panic(expected = "the property function failed")]
    fn run_smoke_test_panics_when_property_fails() {
        run_smoke_test(&FakeFuzzTest { succeeds: false });
    }
}
