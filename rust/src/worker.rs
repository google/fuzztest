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

use super::domains::{GenericCorpusValue, GenericDomain};
use super::internal::{BoxedFuzzTest, FuzzTest};
use super::options::{self, CentipedeArgs, ExecutionAction};
use ::engine::engine_ffi;
use ::engine::{
    BytesSink, CoverageDomainRegistry, DiagnosticSink, ExecuteContext, FeedbackSink, InputSink,
};
use spin::Mutex;
use std::env;
use std::ffi::{c_int, OsStr};
use std::fs;
use std::io::{self, Write as _};
use std::path::Path;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::time::Instant;

/// The DiagnosticSink provided by the engine while creating the adapter.
///
/// Storing the `DiagnosticSink` in this global is necessary because C callbacks (e.g.,
/// sanitizer hooks in `crash_handler.rs`) do not have access to the adapter instance and must rely
/// on a global lookup to report crashes.
static DIAGNOSTIC_SINK: Mutex<Option<DiagnosticSink>> = Mutex::new(None);

/// A global execution context token.
///
/// This is set to `Some(ExecuteContext)` when the fuzz test is currently executing
/// (inside the `execute` method of `RustFuzzTestAdapter`) and `None` otherwise.
///
/// The inner ExecuteContext is used as a witness token to prove to the fuzzing engine that findings
/// are being emitted during the execution of a test case.
/// A global is necessary because C callbacks (e.g. sanitizer hooks in `crash_handler.rs`) do
/// not have access to the adapter instance.
static EXECUTE_CONTEXT: Mutex<Option<ExecuteContext>> = Mutex::new(None);

/// Sets the global DiagnosticSink.
pub(crate) fn set_diagnostic_sink(sink: DiagnosticSink) {
    let mut guard = DIAGNOSTIC_SINK.lock();
    *guard = Some(sink);
}

/// Clears the global DiagnosticSink, setting it to None.
pub(crate) fn clear_diagnostic_sink() {
    let mut guard = DIAGNOSTIC_SINK.lock();
    *guard = None;
}

/// Emits an error into the DiagnosticSink if the DiagnosticSink is set.
/// This function blocks till it can get the lock on the global DiagnosticSink and is not
/// signal-safe.
pub(crate) fn emit_error(message: &str) {
    if let Some(sink) = DIAGNOSTIC_SINK.lock().as_ref() {
        sink.emit_error(message)
    }
}

/// Emits a finding into the DiagnosticSink if the DiagnosticSink is set.
/// This function blocks till it can get the lock on the global DiagnosticSink and is not
/// signal-safe. Call `try_emit_finding` from a signal handler instead.
pub(crate) fn emit_finding(description: &str, signature: &str) {
    let guard = EXECUTE_CONTEXT.lock();
    let token =
        guard.as_ref().expect("emit_finding should only be called when a test is executing");
    DIAGNOSTIC_SINK
        .lock()
        .as_ref()
        .expect("diagnostic sink should be present when a test is executing")
        .emit_finding(token, description, signature);
}

/// Emits a finding into the DiagnosticSink if the DiagnosticSink is set, and we are in the Execute
/// callback context. It only tries once to get the lock. The return value indicates if the finding
/// was successfully emitted.
///
/// This function return false if:
/// - it could not get the lock on DiagnosticSink.
/// - it got the lock but the global DiagnosticSink was not set.
/// - diagnostic sink was set but the test was not executing.
pub(crate) fn try_emit_finding(description: &str, signature: &str) -> bool {
    let Some(diagnostic_guard) = DIAGNOSTIC_SINK.try_lock() else {
        return false;
    };
    let Some(sink) = diagnostic_guard.as_ref() else {
        return false;
    };
    let Some(execution_guard) = EXECUTE_CONTEXT.try_lock() else {
        return false;
    };
    let Some(token) = execution_guard.as_ref() else {
        return false;
    };
    sink.emit_finding(token, description, signature);
    true
}

// We double-box the input because `GenericCorpusValue` is a fat pointer (`Box<dyn CloneAny>`),
// which cannot be directly represented as a single `usize` in `FuzzTestInputHandle` for FFI.
// By boxing it again, we get a thin pointer (`Box<Box<dyn CloneAny>>`) that can be safely cast
// to `usize`.
// The memory is reclaimed when the engine calls `free_input`, which reconstructs the outer
// box using `Box::from_raw` and drops it, thereby dropping the inner box and the value.
fn pack_input(input: GenericCorpusValue) -> engine_ffi::FuzzTestInputHandle {
    let ptr = Box::into_raw(Box::new(input));
    engine_ffi::FuzzTestInputHandle(ptr as usize)
}

/// A guard that manages the global `EXECUTE_CONTEXT` state, setting it to `Some` on creation,
/// and resetting to `None` on drop.
#[must_use = "the execution guard must be held for the duration of the test execution to record findings and crashes"]
struct ExecutionGuard;

impl ExecutionGuard {
    /// Enters the execution context by setting `EXECUTE_CONTEXT`.
    ///
    /// # Safety
    /// The caller must ensure we are in a valid state to create an `ExecuteContext`.
    unsafe fn enter() -> Self {
        *EXECUTE_CONTEXT.lock() = Some(unsafe { ExecuteContext::new() });
        Self
    }
}

impl Drop for ExecutionGuard {
    fn drop(&mut self) {
        *EXECUTE_CONTEXT.lock() = None;
    }
}

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

    pub fn set_up_coverage_domains(&self, registry: &mut CoverageDomainRegistry) {
        registry.set_up_sancov_domains();
    }

    pub fn get_random_seed_input(&self, sink: &mut InputSink) {
        match self.with_domains(|domains| domains.init(&mut rand::rng())) {
            Ok(value) => sink.emit(pack_input(value)),
            Err(e) => emit_error(&format!("Failed to initialize random seed: {:?}", e)),
        }
    }

    pub fn mutate(&self, origin: &GenericCorpusValue, shrink: bool, sink: &mut InputSink) {
        let mut mutant = origin.clone();
        match self.with_domains(|domains| domains.mutate(&mut mutant, &mut rand::rng(), shrink)) {
            Ok(()) => sink.emit(pack_input(mutant)),
            Err(e) => emit_error(&format!("Failed to mutate: {:?}", e)),
        }
    }

    pub fn execute(&self, input: &GenericCorpusValue, sink: &mut FeedbackSink) {
        // TODO(the-shank): modify this in order to support persistent mode and batch execution.
        static CLEAR_STARTUP_COVERAGE: AtomicBool = AtomicBool::new(true);
        // Called even in unguided mode: besides clearing coverage, this frees the SanCov state of
        // threads that exited during the previous execution, which would otherwise accumulate.
        coverage::prepare_coverage(CLEAR_STARTUP_COVERAGE.swap(false, Ordering::AcqRel));

        // SAFETY: We are currently in the `execute` callback of `RustFuzzTestAdapter`.
        let _guard = unsafe { ExecutionGuard::enter() };

        let result = self.fuzz_test.execute(input);

        if !options::get_fuzztest_options().unguided {
            coverage::post_process_coverage(false);
            sink.emit_sancov_features();
        }

        if !result {
            // TODO(the-shank): the signature should be different for different panics. Currently,
            // all test failures due to panics are reported with the same signature.
            emit_finding("Property function ran but crashed.", "Unwinding panic");
        }
    }

    pub fn serialize_input_content(&self, input: &GenericCorpusValue, sink: &mut BytesSink) {
        match self.with_domains(|domains| domains.serialize_corpus(input)) {
            Ok(serialized) => sink.emit(&serialized),
            Err(e) => emit_error(&format!("Failed to serialize input: {:?}", e)),
        }
    }

    pub fn deserialize_input_content(&self, content: &[u8], sink: &mut InputSink) {
        match self.with_domains(|domains| domains.parse_corpus(content)) {
            Ok(value) => sink.emit(pack_input(value)),
            Err(e) => emit_error(&format!("Failed to deserialize input: {:?}", e)),
        }
    }

    pub fn free_input(&self, input: engine_ffi::FuzzTestInputHandle) {
        if input.0 != 0 {
            // SAFETY: The engine guarantees `input` was created by
            // `deserialize_input_content_callback` (or `emit` in `InputSink`) and has
            // not been freed yet.
            unsafe {
                let _ = Box::from_raw(input.0 as *mut GenericCorpusValue);
            }
        }
    }
}

/// Identifies a registered fuzz test and constructs its [`FuzzTest`] instances.
pub struct RustFuzzTestAdapterManager {
    /// Rust module-qualified name of the fuzz test.
    pub test_name: &'static str,
    /// Factory that constructs a fresh [`BoxedFuzzTest`] for the test.
    pub fuzz_test_factory: fn() -> BoxedFuzzTest,
}

fn binary_id_from_argv0(argv0: Option<&OsStr>) -> &[u8] {
    argv0.and_then(|arg| Path::new(arg).file_name()).unwrap_or_default().as_encoded_bytes()
}

impl RustFuzzTestAdapterManager {
    pub fn get_binary_id(&self, sink: &mut BytesSink) {
        // The engine asks for the binary ID at most once per process, so nothing is cached. A
        // missing `argv[0]` yields an empty ID and a non-UTF-8 one is emitted as is: this runs
        // inside an `extern "C"` callback and must not panic.
        let argv0 = env::args_os().next();
        sink.emit(binary_id_from_argv0(argv0.as_deref()));
    }

    // Replaces "::" with "." to avoid parsing issues in Centipede. Centipede uses ":" as a
    // separator in CENTIPEDE_RUNNER_FLAGS and its parser replaces all ":" with "\0", which would
    // truncate Rust paths.
    pub fn get_test_name(&self, sink: &mut BytesSink) {
        let name = self.test_name.replace("::", ".");
        sink.emit(name.as_bytes());
    }

    pub fn construct_adapter(&self) -> RustFuzzTestAdapter {
        RustFuzzTestAdapter { fuzz_test: self.construct_fuzz_test() }
    }

    /// Constructs a new [`BoxedFuzzTest`] instance for this test.
    pub fn construct_fuzz_test(&self) -> BoxedFuzzTest {
        (self.fuzz_test_factory)()
    }
}

/// # Safety
///
/// The caller must ensure that:
/// * `ctx` is a valid pointer to the `RustFuzzTestAdapterManager` passed during initialization.
/// * `sink` is a valid pointer to a `FuzzTestBytesSink` whose lifetime extends for the duration of
///   this call.
pub unsafe extern "C" fn get_binary_id_callback(
    ctx: *mut engine_ffi::FuzzTestAdapterManagerCtx,
    sink: *const engine_ffi::FuzzTestBytesSink,
) {
    // SAFETY: The engine guarantees `ctx` is a valid pointer to the `RustFuzzTestAdapterManager`
    // passed during initialization.
    let manager = unsafe { &*(ctx as *const RustFuzzTestAdapterManager) };
    // SAFETY: The engine guarantees `sink` is a valid pointer to a `FuzzTestBytesSink`
    // whose lifetime extends for the duration of this call.
    let mut safe_sink = unsafe { BytesSink::from_raw(sink) };
    manager.get_binary_id(&mut safe_sink);
}

/// # Safety
///
/// The caller must ensure that:
/// * `ctx` is a valid pointer to the `RustFuzzTestAdapterManager` passed during initialization.
/// * `sink` is a valid pointer to a `FuzzTestBytesSink` whose lifetime extends for the duration of
///   this call.
pub unsafe extern "C" fn get_test_name_callback(
    ctx: *mut engine_ffi::FuzzTestAdapterManagerCtx,
    sink: *const engine_ffi::FuzzTestBytesSink,
) {
    // SAFETY: The engine guarantees `ctx` is a valid pointer to the `RustFuzzTestAdapterManager`
    // passed during initialization.
    let manager = unsafe { &*(ctx as *const RustFuzzTestAdapterManager) };
    // SAFETY: The engine guarantees `sink` is a valid pointer to a `FuzzTestBytesSink`
    // whose lifetime extends for the duration of this call.
    let mut safe_sink = unsafe { BytesSink::from_raw(sink) };
    manager.get_test_name(&mut safe_sink);
}

/// # Safety
///
/// The caller must ensure that:
/// * `ctx` is a valid pointer to the `RustFuzzTestAdapterManager` passed during initialization.
/// * `diagnostic_sink` is a valid pointer to a `FuzzTestDiagnosticSink` whose lifetime extends
///   until `FreeCtx` is called on the adapter.
/// * `adapter_out` is a valid pointer to write the output `FuzzTestAdapter`.
pub unsafe extern "C" fn construct_adapter_callback(
    ctx: *mut engine_ffi::FuzzTestAdapterManagerCtx,
    diagnostic_sink: *const engine_ffi::FuzzTestDiagnosticSink,
    adapter_out: *mut engine_ffi::FuzzTestAdapter,
) {
    // SAFETY: The engine guarantees `ctx` is a valid pointer to the `RustFuzzTestAdapterManager`
    // passed during initialization.
    let manager = unsafe { &*(ctx as *const RustFuzzTestAdapterManager) };

    // SAFETY: The engine guarantees `diagnostic_sink` is a valid pointer to a
    // `FuzzTestDiagnosticSink` whose lifetime extends until `FreeCtx` is called on the adapter.
    let safe_sink = unsafe { DiagnosticSink::from_raw(diagnostic_sink) };

    set_diagnostic_sink(safe_sink);

    // NOTE: `safe_sink` is not passed to `construct_adapter` or stored in `RustFuzzTestAdapter`.
    // Instead, it is maintained in the global `DIAGNOSTIC_SINK` mutex via `set_diagnostic_sink`.
    // This is necessary because C callbacks (e.g., sanitizer hooks in `crash_handler.rs`) do not
    // have access to the adapter `self` pointer and must rely on a global lookup to report crashes.
    let adapter = manager.construct_adapter();
    let boxed_adapter = Box::new(adapter);
    // TODO(b/587358247): Implement missing callbacks on `RustFuzzTestAdapter`.
    // SAFETY: The engine guarantees `adapter_out` is a valid pointer to write the output adapter.
    // The returned raw pointer `ctx` will be managed and eventually freed by `free_ctx_callback`.
    unsafe {
        *adapter_out = engine_ffi::FuzzTestAdapter {
            ctx: Box::into_raw(boxed_adapter) as *mut engine_ffi::FuzzTestAdapterCtx,
            set_up_coverage_domains: Some(set_up_coverage_domains_callback),
            // The optional callbacks that have no implementation yet stay null. The engine then
            // uses its own fallback: no preset seeds, `mutate` instead of `cross_over`, and no
            // input metadata.
            get_preset_seed_inputs: None,
            get_random_seed_input: Some(get_random_seed_input_callback),
            mutate: Some(mutate_callback),
            cross_over: None,
            execute: Some(execute_callback),
            serialize_input_content: Some(serialize_input_content_callback),
            deserialize_input_content: Some(deserialize_input_content_callback),
            serialize_input_metadata: None,
            update_input_metadata: None,
            free_input: Some(free_input_callback),
            free_ctx: Some(free_ctx_callback),
        };
    }
}

/// # Safety
///
/// The caller must ensure that:
/// * `ctx` is a valid pointer to the `RustFuzzTestAdapter` created by `construct_adapter_callback`.
/// * `registry` is a valid pointer to `FuzzTestCoverageDomainRegistry`.
pub unsafe extern "C" fn set_up_coverage_domains_callback(
    ctx: *mut engine_ffi::FuzzTestAdapterCtx,
    registry: *const engine_ffi::FuzzTestCoverageDomainRegistry,
) {
    // SAFETY: The engine guarantees `ctx` is a valid pointer to the `RustFuzzTestAdapter`
    // created by `construct_adapter_callback`.
    let adapter = unsafe { &*(ctx as *const RustFuzzTestAdapter) };
    // SAFETY: The engine guarantees `registry` is a valid pointer to
    // `FuzzTestCoverageDomainRegistry`.
    let mut registry = unsafe { CoverageDomainRegistry::from_raw(registry) };
    adapter.set_up_coverage_domains(&mut registry);
}

/// # Safety
///
/// The caller must ensure that:
/// * `ctx` is a valid pointer to the `RustFuzzTestAdapter` created by `construct_adapter_callback`.
/// * `sink` is a valid pointer to `FuzzTestInputSink`.
pub unsafe extern "C" fn get_random_seed_input_callback(
    ctx: *mut engine_ffi::FuzzTestAdapterCtx,
    sink: *const engine_ffi::FuzzTestInputSink,
) {
    // SAFETY: The engine guarantees `ctx` is a valid pointer to the `RustFuzzTestAdapter`
    // created by `construct_adapter_callback`.
    let adapter = unsafe { &*(ctx as *const RustFuzzTestAdapter) };
    // SAFETY: The engine guarantees `sink` is a valid pointer to `FuzzTestInputSink`.
    let mut safe_sink = unsafe { InputSink::from_raw(sink) };
    adapter.get_random_seed_input(&mut safe_sink);
}

/// # Safety
///
/// The caller must ensure that:
/// * `ctx` is a valid pointer to the `RustFuzzTestAdapter` created by `construct_adapter_callback`.
/// * `origin` is a valid `FuzzTestInputHandle` pointing to a heap-allocated `GenericCorpusValue`
///   managed by the framework.
/// * `sink` is a valid pointer to `FuzzTestInputSink`.
pub unsafe extern "C" fn mutate_callback(
    ctx: *mut engine_ffi::FuzzTestAdapterCtx,
    origin: engine_ffi::FuzzTestInputHandle,
    shrink: c_int,
    sink: *const engine_ffi::FuzzTestInputSink,
) {
    // SAFETY: The engine guarantees `ctx` is a valid pointer to the `RustFuzzTestAdapter`
    // created by `construct_adapter_callback`.
    let adapter = unsafe { &*(ctx as *const RustFuzzTestAdapter) };
    // SAFETY: The engine guarantees `origin` is a valid `FuzzTestInputHandle` pointing to
    // a heap-allocated `GenericCorpusValue` managed by the framework.
    let origin_ref = unsafe { &*(origin.0 as *const GenericCorpusValue) };
    // SAFETY: The engine guarantees `sink` is a valid pointer to `FuzzTestInputSink`.
    let mut safe_sink = unsafe { InputSink::from_raw(sink) };
    adapter.mutate(origin_ref, shrink != 0, &mut safe_sink);
}

/// # Safety
///
/// The caller must ensure that:
/// * `ctx` is a valid pointer to the `RustFuzzTestAdapter` created by `construct_adapter_callback`.
/// * `input` is a valid `FuzzTestInputHandle` pointing to a heap-allocated `GenericCorpusValue`
///   managed by the framework.
/// * `sink` is a valid pointer to `FuzzTestFeedbackSink`.
pub unsafe extern "C" fn execute_callback(
    ctx: *mut engine_ffi::FuzzTestAdapterCtx,
    input: engine_ffi::FuzzTestInputHandle,
    sink: *const engine_ffi::FuzzTestFeedbackSink,
) {
    // SAFETY: The engine guarantees `ctx` is a valid pointer to the `RustFuzzTestAdapter`
    // created by `construct_adapter_callback`.
    let adapter = unsafe { &*(ctx as *const RustFuzzTestAdapter) };
    // SAFETY: The engine guarantees `input` is a valid `FuzzTestInputHandle` pointing to
    // a heap-allocated `GenericCorpusValue` managed by the framework.
    let input_ref = unsafe { &*(input.0 as *const GenericCorpusValue) };
    // SAFETY: The engine guarantees `sink` is a valid pointer to `FuzzTestFeedbackSink`.
    let mut safe_sink = unsafe { FeedbackSink::from_raw(sink) };

    adapter.execute(input_ref, &mut safe_sink);
}

/// # Safety
///
/// The caller must ensure that:
/// * `ctx` is a valid pointer to the `RustFuzzTestAdapter` created by `construct_adapter_callback`.
/// * `input` is a valid `FuzzTestInputHandle` pointing to a heap-allocated `GenericCorpusValue`
///   managed by the framework.
/// * `sink` is a valid pointer to `FuzzTestBytesSink`.
pub unsafe extern "C" fn serialize_input_content_callback(
    ctx: *mut engine_ffi::FuzzTestAdapterCtx,
    input: engine_ffi::FuzzTestInputHandle,
    sink: *const engine_ffi::FuzzTestBytesSink,
) {
    // SAFETY: The engine guarantees `ctx` is a valid pointer to the `RustFuzzTestAdapter`
    // created by `construct_adapter_callback`.
    let adapter = unsafe { &*(ctx as *const RustFuzzTestAdapter) };
    // SAFETY: The engine guarantees `input` is a valid `FuzzTestInputHandle` pointing to
    // a heap-allocated `GenericCorpusValue` managed by the framework.
    let input_ref = unsafe { &*(input.0 as *const GenericCorpusValue) };
    // SAFETY: The engine guarantees `sink` is a valid pointer to `FuzzTestBytesSink`.
    let mut safe_sink = unsafe { BytesSink::from_raw(sink) };
    adapter.serialize_input_content(input_ref, &mut safe_sink);
}

/// # Safety
///
/// The caller must ensure that:
/// * `ctx` is a valid pointer to the `RustFuzzTestAdapter` created by `construct_adapter_callback`.
/// * `content` is a valid pointer to `FuzzTestBytesView` containing serialized input content.
/// * `sink` is a valid pointer to `FuzzTestInputSink`.
pub unsafe extern "C" fn deserialize_input_content_callback(
    ctx: *mut engine_ffi::FuzzTestAdapterCtx,
    content: *const engine_ffi::FuzzTestBytesView,
    sink: *const engine_ffi::FuzzTestInputSink,
) {
    // SAFETY: The engine guarantees `ctx` is a valid pointer to the `RustFuzzTestAdapter`
    // created by `construct_adapter_callback`.
    let adapter = unsafe { &*(ctx as *const RustFuzzTestAdapter) };
    // SAFETY: The engine guarantees `content` is a valid pointer to `FuzzTestBytesView`
    // containing serialized input content.
    let bytes = unsafe { &*(*content).to_bytes() };
    // SAFETY: The engine guarantees `sink` is a valid pointer to `FuzzTestInputSink`.
    let mut safe_sink = unsafe { InputSink::from_raw(sink) };
    adapter.deserialize_input_content(bytes, &mut safe_sink);
}

/// # Safety
///
/// The caller must ensure that:
/// * `ctx` is a valid pointer to the `RustFuzzTestAdapter` created by `construct_adapter_callback`.
/// * `input` is a valid `FuzzTestInputHandle` pointing to a heap-allocated `GenericCorpusValue`
///   managed by the framework that has not been freed yet.
pub unsafe extern "C" fn free_input_callback(
    ctx: *mut engine_ffi::FuzzTestAdapterCtx,
    input: engine_ffi::FuzzTestInputHandle,
) {
    // SAFETY: The engine guarantees `ctx` is a valid pointer to the `RustFuzzTestAdapter`
    // created by `construct_adapter_callback`.
    let adapter = unsafe { &*(ctx as *const RustFuzzTestAdapter) };
    adapter.free_input(input);
}

/// # Safety
///
/// The caller must ensure that:
/// * `ctx` is a valid pointer to the `RustFuzzTestAdapter` created by `construct_adapter_callback`.
pub unsafe extern "C" fn free_ctx_callback(ctx: *mut engine_ffi::FuzzTestAdapterCtx) {
    if !ctx.is_null() {
        // SAFETY: The engine guarantees `ctx` is a valid pointer to the `RustFuzzTestAdapter`
        // created by `construct_adapter_callback`.
        let ptr = ctx as *mut RustFuzzTestAdapter;
        drop(unsafe { Box::from_raw(ptr) });

        clear_diagnostic_sink();
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

pub enum WorkerStatus {
    Success,
    Failure,
}

/// Processes and executes a fuzz test using the provided [`RustFuzzTestAdapterManager`].
///
/// This function serves as the primary entry point for running a fuzz test:
///
/// 1. Worker mode: registers the sanitizer crash handler and offers the test to the fuzzing engine.
///    - If the binary was spawned as a worker process by the fuzzing engine, control remains in the
///      engine loop until it completes.
///    - Returns cleanly on [`WorkerStatus::Success`], so that the harness continues with the next
///      test, and exits the process with status 1 on [`WorkerStatus::Failure`].
/// 2. Otherwise, runs the action selected by the FuzzTest options: runs the fuzzing controller
///    (standalone fuzzing or crash replay), or falls back to a short local smoke test, as in
///    standard `blaze test` or `cargo test` runs.
///
/// # Panics
///
/// Panics if the FuzzTest options cannot be turned into an execution action, if the controller
/// reports a failure (when fuzzing or listing crashes), or if the smoke test panics (see
/// [`run_smoke_test`]).
pub fn process(manager: RustFuzzTestAdapterManager) {
    super::crash_handler::register_crash_handler();

    match maybe_run_as_worker(&manager) {
        // The harness continues with the next test.
        Some(WorkerStatus::Success) => return,
        Some(WorkerStatus::Failure) => process::exit(1),
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
    let status = run_standalone_mode(manager, args);
    if status == engine_ffi::FuzzTestControllerStatus::Failure {
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
            let _ = writeln!(
                io::stderr(),
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
                // The status is ignored: replaying a crash is expected to report a failure, and
                // the remaining crashes should still be replayed.
                let _ = run_standalone_mode(manager, replay_args);
            }
            Ok(None) => unreachable!("replaying a crash always runs Centipede"),
            Err(e) => {
                let _ = writeln!(io::stderr(), "warning: crash {crash_id} was not replayed: {e:#}");
            }
        }
    }
}

fn make_ffi_manager(manager: &RustFuzzTestAdapterManager) -> engine_ffi::FuzzTestAdapterManager {
    let ctx =
        manager as *const RustFuzzTestAdapterManager as *mut engine_ffi::FuzzTestAdapterManagerCtx;

    engine_ffi::FuzzTestAdapterManager {
        ctx,
        get_binary_id: Some(get_binary_id_callback),
        get_test_name: Some(get_test_name_callback),
        construct_adapter: Some(construct_adapter_callback),
    }
}

/// Attempts to run the fuzz test in Centipede worker mode using the FFI engine interface.
///
/// This function constructs a C-compatible [`engine_ffi::FuzzTestAdapterManager`] wrapping
/// the given `manager` with required callback function pointers (`get_binary_id_callback`,
/// `get_test_name_callback`, `construct_adapter_callback`), and invokes
/// [`engine_ffi::FuzzTestWorkerMaybeRun`].
///
/// # Returns
/// - `Some(WorkerStatus::Success)`: The process ran in worker mode and completed successfully.
/// - `Some(WorkerStatus::Failure)`: The process ran in worker mode and encountered a failure.
/// - `None`: Worker mode was not requested (`kFuzzTestWorkerNotRequired`). The caller decides what
///   to run instead.
fn maybe_run_as_worker(manager: &RustFuzzTestAdapterManager) -> Option<WorkerStatus> {
    let ffi_manager = make_ffi_manager(manager);

    // SAFETY: `ffi_manager` wraps `manager`, which is alive for the duration of this call, and
    // `FuzzTestWorkerMaybeRun` does not retain `ffi_manager` or its context after it returns.
    // `ffi_manager` contains valid C-compatible function pointer callbacks.
    let status = unsafe { engine_ffi::FuzzTestWorkerMaybeRun(&ffi_manager) };

    match status {
        engine_ffi::FuzzTestWorkerStatus::Success => Some(WorkerStatus::Success),
        engine_ffi::FuzzTestWorkerStatus::Failure => Some(WorkerStatus::Failure),
        engine_ffi::FuzzTestWorkerStatus::NotRequired => None,
    }
}

fn run_standalone_mode(
    manager: &RustFuzzTestAdapterManager,
    centipede_args: CentipedeArgs,
) -> engine_ffi::FuzzTestControllerStatus {
    let ffi_manager = make_ffi_manager(manager);

    // SAFETY: `ffi_manager` wraps `manager` which is guaranteed to be alive. `centipede_args` is
    // alive until the end of this function, since we have the ownership, ensuring that the
    // pointers passed to `FuzzTestControllerRun` remain valid.
    unsafe { engine_ffi::FuzzTestControllerRun(&ffi_manager, &centipede_args.as_bytes_views()) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;
    use std::sync::{Arc, Mutex};

    struct FakeDomain;

    impl GenericDomain for FakeDomain {
        fn init(&mut self, _rng: &mut dyn rand::Rng) -> anyhow::Result<GenericCorpusValue> {
            Ok(Box::new(42u32))
        }

        fn mutate(
            &mut self,
            corpus_value: &mut GenericCorpusValue,
            _rng: &mut dyn rand::Rng,
            _only_shrink: bool,
        ) -> anyhow::Result<()> {
            let value =
                corpus_value.downcast_mut::<u32>().expect("FakeDomain corpus value should be u32");
            *value += 1;
            Ok(())
        }

        fn parse_corpus(&self, data: &[u8]) -> anyhow::Result<GenericCorpusValue> {
            let value = u32::try_from(data.len()).unwrap_or(0);
            Ok(Box::new(value))
        }

        fn serialize_corpus(&self, val: &GenericCorpusValue) -> anyhow::Result<Vec<u8>> {
            let value = val.downcast_ref::<u32>().expect("FakeDomain corpus value should be u32");
            Ok(value.to_le_bytes().to_vec())
        }
    }

    struct FakeFuzzTest {
        domains: Arc<Mutex<FakeDomain>>,
    }

    impl FuzzTest for FakeFuzzTest {
        fn name(&self) -> &'static str {
            "fake_fuzz_test"
        }

        fn activate(&mut self) {}

        fn mutate(&mut self) {}

        fn execute(&self, _args: &GenericCorpusValue) -> bool {
            true
        }

        fn domains(&self) -> Arc<Mutex<dyn GenericDomain>> {
            Arc::clone(&self.domains) as Arc<Mutex<dyn GenericDomain>>
        }
    }

    struct InputProbe {
        domains: Arc<Mutex<dyn GenericDomain>>,
        lock_was_released: bool,
        emitted: Vec<engine_ffi::FuzzTestInputHandle>,
    }

    struct BytesProbe {
        domains: Arc<Mutex<dyn GenericDomain>>,
        lock_was_released: bool,
        emitted: Vec<u8>,
    }

    /// Records `input` in the [`InputProbe`] pointed to by `ctx` and checks that `domains` is
    /// unlocked during the callback.
    ///
    /// # Safety
    ///
    /// The caller must ensure that `ctx` is a non-null, properly aligned pointer to a live, valid
    /// [`InputProbe`] that is exclusively accessed on the current thread for the duration of this
    /// call (with no overlapping [`InputProbe`] borrows).
    unsafe extern "C" fn record_input(
        ctx: *mut engine_ffi::FuzzTestInputSinkCtx,
        input: engine_ffi::FuzzTestInputHandle,
    ) {
        // SAFETY: The caller guarantees `ctx` points to a live, valid, exclusively accessed
        // `InputProbe` on this thread for the duration of this call.
        let probe = unsafe { &mut *(ctx as *mut InputProbe) };
        probe.lock_was_released = probe.domains.try_lock().is_ok();
        probe.emitted.push(input);
    }

    /// Records serialized bytes in the [`BytesProbe`] pointed to by `ctx` and checks that
    /// `domains` is unlocked during the callback.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// * `ctx` is a non-null, properly aligned pointer to a live, valid [`BytesProbe`] that is
    ///   exclusively accessed on the current thread for the duration of this call (with no
    ///   overlapping [`BytesProbe`] borrows).
    /// * `view` is a non-null, properly aligned pointer to an initialized `FuzzTestBytesView` whose
    ///   slice (`(*view).to_bytes()`) is valid for reads of `u8` for the duration of this call.
    unsafe extern "C" fn record_bytes(
        ctx: *mut engine_ffi::FuzzTestBytesSinkCtx,
        view: *const engine_ffi::FuzzTestBytesView,
    ) {
        // SAFETY: The caller guarantees `ctx` points to a live, valid, exclusively accessed
        // `BytesProbe` on this thread for the duration of this call.
        let probe = unsafe { &mut *(ctx as *mut BytesProbe) };
        // SAFETY: The caller guarantees `view` points to a valid `FuzzTestBytesView` whose
        // backing byte slice is valid for reads for the duration of this call.
        let bytes = unsafe { &*(*view).to_bytes() };
        probe.lock_was_released = probe.domains.try_lock().is_ok();
        probe.emitted.extend_from_slice(bytes);
    }

    fn make_fake_adapter() -> (RustFuzzTestAdapter, Arc<Mutex<dyn GenericDomain>>) {
        let domains = Arc::new(Mutex::new(FakeDomain));
        let domains_dyn: Arc<Mutex<dyn GenericDomain>> =
            Arc::clone(&domains) as Arc<Mutex<dyn GenericDomain>>;
        let adapter = RustFuzzTestAdapter { fuzz_test: Box::new(FakeFuzzTest { domains }) };
        (adapter, domains_dyn)
    }

    #[gtest]
    fn binary_id_from_argv0_extracts_file_name_and_handles_edge_cases() {
        expect_eq!(
            binary_id_from_argv0(Some(OsStr::new("/usr/local/bin/my_fuzzer"))),
            b"my_fuzzer"
        );
        expect_eq!(binary_id_from_argv0(None), b"");
        expect_eq!(binary_id_from_argv0(Some(OsStr::new(""))), b"");
        expect_eq!(binary_id_from_argv0(Some(OsStr::new("/"))), b"");
    }

    #[cfg(unix)]
    #[gtest]
    fn binary_id_from_argv0_preserves_non_utf8_bytes() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let raw = OsString::from_vec(b"/tmp/fuzz_\xff_bin".to_vec());
        expect_eq!(binary_id_from_argv0(Some(raw.as_os_str())), b"fuzz_\xff_bin");
    }

    fn assert_input_sink_releases_lock(
        adapter: &RustFuzzTestAdapter,
        domains: Arc<Mutex<dyn GenericDomain>>,
        call: impl FnOnce(&mut InputSink),
    ) {
        let mut probe = InputProbe { domains, lock_was_released: false, emitted: Vec::new() };
        let raw_sink = engine_ffi::FuzzTestInputSink {
            ctx: (&raw mut probe) as *mut engine_ffi::FuzzTestInputSinkCtx,
            emit: Some(record_input),
        };
        {
            // SAFETY: `raw_sink` points to a valid local `FuzzTestInputSink`, `raw_sink.ctx`
            // points to `probe`, and `record_input` upholds `InputSink`'s contract while `probe`
            // remains alive and is only accessed via `sink` on this thread until this block ends.
            let mut sink = unsafe { InputSink::from_raw(&raw_sink) };
            call(&mut sink);
        }

        expect_true!(probe.lock_was_released);
        expect_eq!(probe.emitted.len(), 1);
        for handle in probe.emitted {
            adapter.free_input(handle);
        }
    }

    #[gtest]
    fn get_random_seed_input_releases_domains_lock_before_sink() {
        let (adapter, domains) = make_fake_adapter();
        assert_input_sink_releases_lock(&adapter, domains, |sink| {
            adapter.get_random_seed_input(sink);
        });
    }

    #[gtest]
    fn mutate_releases_domains_lock_before_sink() {
        let (adapter, domains) = make_fake_adapter();
        let origin: GenericCorpusValue = Box::new(10u32);
        assert_input_sink_releases_lock(&adapter, domains, |sink| {
            adapter.mutate(&origin, false, sink);
        });
    }

    #[gtest]
    fn serialize_input_content_releases_domains_lock_before_sink() {
        let (adapter, domains) = make_fake_adapter();
        let input: GenericCorpusValue = Box::new(42u32);
        let mut probe = BytesProbe { domains, lock_was_released: false, emitted: Vec::new() };
        let raw_sink = engine_ffi::FuzzTestBytesSink {
            ctx: (&raw mut probe) as *mut engine_ffi::FuzzTestBytesSinkCtx,
            emit: Some(record_bytes),
        };
        {
            // SAFETY: `raw_sink` points to a valid local `FuzzTestBytesSink`, `raw_sink.ctx`
            // points to `probe`, and `record_bytes` upholds `BytesSink`'s contract while `probe`
            // remains alive and is only accessed via `sink` on this thread until this block ends.
            let mut sink = unsafe { BytesSink::from_raw(&raw_sink) };
            adapter.serialize_input_content(&input, &mut sink);
        }

        expect_true!(probe.lock_was_released);
        expect_eq!(probe.emitted, 42u32.to_le_bytes());
    }

    #[gtest]
    fn deserialize_input_content_releases_domains_lock_before_sink() {
        let (adapter, domains) = make_fake_adapter();
        assert_input_sink_releases_lock(&adapter, domains, |sink| {
            adapter.deserialize_input_content(b"abcd", sink);
        });
    }
}
