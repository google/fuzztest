use super::domains::GenericCorpusValue;
use super::internal::{BoxedFuzzTest, FuzzTest};
use super::options::{self, CentipedeArgs, ExecutionAction};
use ::engine::engine_ffi;
use ::engine::{
    BytesSink, CoverageDomainRegistry, DiagnosticSink, ExecuteContext, FeedbackSink, InputSink,
};
use spin::Mutex;
use std::ffi::CString;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::LazyLock;

/// The DiagnosticSink provided by the engine while creating the adapter.
///
/// Storing the `DiagnosticSink` in this global is necessary because C death callbacks (e.g.,
/// sanitizer traps in `crash_handler.rs`) do not have access to the adapter instance and must rely
/// on a global lookup to report crashes.
static DIAGNOSTIC_SINK: Mutex<Option<DiagnosticSink>> = Mutex::new(None);

/// A global execution context token.
///
/// This is set to `Some(ExecuteContext)` when the fuzz test is currently executing
/// (inside the `execute` method of `RustFuzzTestAdapter`) and `None` otherwise.
///
/// The inner ExecuteContext is used as a witness token to prove to the fuzzing engine that findings
/// are being emitted during the execution of a test case.
/// A global is necessary because C death callbacks (e.g. sanitizer traps in `crash_handler.rs`) do
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
    DIAGNOSTIC_SINK.lock().as_ref().map(|sink| sink.emit_error(message));
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
#[allow(dead_code)]
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
    return true;
}

// We double-box the input because `GenericCorpusValue` is a fat pointer (`Box<dyn Any>`),
// which cannot be directly represented as a single `usize` in `FuzzTestInputHandle` for FFI.
// By boxing it again, we get a thin pointer (`Box<Box<dyn Any>>`) that can be safely cast
// to `usize`.
// The memory is reclaimed when the engine calls `free_input`, which reconstructs the outer
// box using `Box::from_raw` and drops it, thereby dropping the inner box and the value.
fn pack_input(input: GenericCorpusValue) -> engine_ffi::FuzzTestInputHandle {
    let ptr = Box::into_raw(Box::new(input));
    engine_ffi::FuzzTestInputHandle(ptr as usize)
}

/// A guard that manages the global `EXECUTE_CONTEXT` state, setting it to `Some` on creation,
/// and resetting to `None` on drop.
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

pub struct RustFuzzTestAdapter {
    fuzz_test: BoxedFuzzTest,
}

impl RustFuzzTestAdapter {
    pub fn set_up_coverage_domains(&self, registry: &mut CoverageDomainRegistry) {
        registry.set_up_sancov_domains();
    }

    pub fn get_preset_seed_inputs(&self, _sink: &mut InputSink) {
        // TODO(the-shank): implement this once the macro has support for specifying preset seed
        // inputs
    }

    pub fn get_random_seed_input(&self, sink: &mut InputSink) {
        match self.fuzz_test.domains().init(&mut rand::rng()) {
            Ok(val) => {
                sink.emit(pack_input(val));
            }
            Err(e) => {
                emit_error(&format!("Failed to initialize random seed: {:?}", e));
            }
        }
    }

    pub fn mutate(&self, origin: &GenericCorpusValue, shrink: bool, sink: &mut InputSink) {
        let mut mutant = origin.clone();

        if let Err(e) = self.fuzz_test.domains().mutate(&mut mutant, &mut rand::rng(), shrink) {
            emit_error(&format!("Failed to mutate: {:?}", e));
            return;
        }

        sink.emit(pack_input(mutant));
    }

    pub fn cross_over(
        &self,
        origin: &GenericCorpusValue,
        _other: &GenericCorpusValue,
        sink: &mut InputSink,
    ) {
        // TODO(the-shank): implement cross_over. Currently we are just calling mutate.
        self.mutate(origin, false, sink);
    }

    pub fn execute(&self, input: &GenericCorpusValue, sink: &mut FeedbackSink) {
        // TODO(the-shank): modify this in order to support persistent mode and batch execution.
        static CLEAR_STARTUP_COVERAGE: AtomicBool = AtomicBool::new(true);
        coverage::prepare_coverage(CLEAR_STARTUP_COVERAGE.swap(false, Ordering::AcqRel));

        // SAFETY: We are currently in the `execute` callback of `RustFuzzTestAdapter`.
        let _guard = unsafe { ExecutionGuard::enter() };

        let result = self.fuzz_test.execute(input);

        coverage::post_process_coverage(false);

        sink.emit_sancov_features();

        if !result {
            // TODO(the-shank): the signature should be different for different panics. Currently,
            // all test failures due to panics are reported with the same signature.
            emit_finding("Property function ran but crashed.", "Unwinding panic");
        }
    }

    pub fn serialize_input_content(&self, input: &GenericCorpusValue, sink: &mut BytesSink) {
        match self.fuzz_test.domains().serialize_corpus(input) {
            Ok(serialized) => {
                sink.emit(&serialized);
            }
            Err(e) => {
                emit_error(&format!("Failed to serialize input: {:?}", e));
            }
        }
    }

    pub fn deserialize_input_content(&self, content: &[u8], sink: &mut InputSink) {
        match self.fuzz_test.domains().parse_corpus(content) {
            Ok(val) => {
                sink.emit(pack_input(val));
            }
            Err(e) => {
                emit_error(&format!("Failed to deserialize input: {:?}", e));
            }
        }
    }

    pub fn serialize_input_metadata(&self, _input: &GenericCorpusValue, _sink: &mut BytesSink) {
        // TODO(the-shank): to be implemented
    }

    pub fn update_input_metadata(&self, _metadata: &[u8], _input: &mut GenericCorpusValue) {
        // TODO(the-shank): to be implemented
    }

    pub fn free_input(&self, input: engine_ffi::FuzzTestInputHandle) {
        if input.0 != 0 {
            // SAFETY: The engine guarantees `input` was created by `deserialize_input_content_callback`
            // (or `emit` in `InputSink`) and has not been freed yet.
            unsafe {
                let _ = Box::from_raw(input.0 as *mut GenericCorpusValue);
            }
        }
    }
}

pub struct RustFuzzTestAdapterManager {
    pub test_name: &'static str,
    pub fuzz_test_factory: fn() -> BoxedFuzzTest,
}

impl RustFuzzTestAdapterManager {
    pub fn get_binary_id(&self, sink: &mut BytesSink) {
        static ARGV0: LazyLock<CString> = LazyLock::new(|| {
            CString::new(
                Path::new(&std::env::args().nth(0).unwrap())
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or(""),
            )
            .expect("argv[0] should not contain null bytes")
        });
        sink.emit(ARGV0.as_bytes());
    }

    // Replaces "::" with "." to avoid parsing issues in Centipede. Centipede uses ":" as a
    // separator in CENTIPEDE_RUNNER_FLAGS and its parser replaces all ":" with "\0", which would
    // truncate Rust paths.
    pub fn get_test_name(&self, sink: &mut BytesSink) {
        let name = self.test_name.replace("::", ".");
        sink.emit(name.as_bytes());
    }

    pub fn construct_adapter(&self) -> RustFuzzTestAdapter {
        let fuzz_test = (self.fuzz_test_factory)();
        RustFuzzTestAdapter { fuzz_test }
    }

    pub fn construct_fuzz_test(&self) -> BoxedFuzzTest {
        (self.fuzz_test_factory)()
    }
}

/// # Safety
///
/// The caller must ensure that:
/// * `ctx` is a valid pointer to the `RustFuzzTestAdapterManager` passed during initialization.
/// * `sink` is a valid pointer to a `FuzzTestBytesSink` whose lifetime extends for the duration
///   of this call.
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
/// * `sink` is a valid pointer to a `FuzzTestBytesSink` whose lifetime extends for the duration
///   of this call.
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

    // SAFETY: The engine guarantees `diagnostic_sink` is a valid pointer to a `FuzzTestDiagnosticSink`
    // whose lifetime extends until `FreeCtx` is called on the adapter.
    let safe_sink = unsafe { DiagnosticSink::from_raw(diagnostic_sink) };

    set_diagnostic_sink(safe_sink);

    // NOTE: `safe_sink` is not passed to `construct_adapter` or stored in `RustFuzzTestAdapter`.
    // Instead, it is maintained in the global `DIAGNOSTIC_SINK` mutex via `set_diagnostic_sink`.
    // This is necessary because C death callbacks (e.g., sanitizer traps in `crash_handler.rs`) do not
    // have access to the adapter `self` pointer and must rely on a global lookup to report crashes.
    let adapter = manager.construct_adapter();
    let boxed_adapter = Box::new(adapter);
    // SAFETY: The engine guarantees `adapter_out` is a valid pointer to write the output adapter.
    // The returned raw pointer `ctx` will be managed and eventually freed by `free_ctx_callback`.
    unsafe {
        *adapter_out = engine_ffi::FuzzTestAdapter {
            ctx: Box::into_raw(boxed_adapter) as *mut engine_ffi::FuzzTestAdapterCtx,
            set_up_coverage_domains: Some(set_up_coverage_domains_callback),
            get_preset_seed_inputs: Some(get_preset_seed_inputs_callback),
            get_random_seed_input: Some(get_random_seed_input_callback),
            mutate: Some(mutate_callback),
            cross_over: Some(cross_over_callback),
            execute: Some(execute_callback),
            serialize_input_content: Some(serialize_input_content_callback),
            deserialize_input_content: Some(deserialize_input_content_callback),
            serialize_input_metadata: Some(serialize_input_metadata_callback),
            update_input_metadata: Some(update_input_metadata_callback),
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
    // SAFETY: The engine guarantees `registry` is a valid pointer to `FuzzTestCoverageDomainRegistry`.
    let mut registry = unsafe { CoverageDomainRegistry::from_raw(registry) };
    adapter.set_up_coverage_domains(&mut registry);
}

/// # Safety
///
/// The caller must ensure that:
/// * `ctx` is a valid pointer to the `RustFuzzTestAdapter` created by `construct_adapter_callback`.
/// * `sink` is a valid pointer to `FuzzTestInputSink`.
pub unsafe extern "C" fn get_preset_seed_inputs_callback(
    ctx: *mut engine_ffi::FuzzTestAdapterCtx,
    sink: *const engine_ffi::FuzzTestInputSink,
) {
    // SAFETY: The engine guarantees `ctx` is a valid pointer to the `RustFuzzTestAdapter`
    // created by `construct_adapter_callback`.
    let adapter = unsafe { &*(ctx as *const RustFuzzTestAdapter) };
    // SAFETY: The engine guarantees `sink` is a valid pointer to `FuzzTestInputSink`.
    let mut safe_sink = unsafe { InputSink::from_raw(sink) };
    adapter.get_preset_seed_inputs(&mut safe_sink);
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
    shrink: std::ffi::c_int,
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
/// * `origin` is a valid `FuzzTestInputHandle` pointing to a heap-allocated `GenericCorpusValue`
///   managed by the framework.
/// * `other` is a valid `FuzzTestInputHandle` pointing to a heap-allocated `GenericCorpusValue`
///   managed by the framework.
/// * `sink` is a valid pointer to `FuzzTestInputSink`.
pub unsafe extern "C" fn cross_over_callback(
    ctx: *mut engine_ffi::FuzzTestAdapterCtx,
    origin: engine_ffi::FuzzTestInputHandle,
    other: engine_ffi::FuzzTestInputHandle,
    sink: *const engine_ffi::FuzzTestInputSink,
) {
    // SAFETY: The engine guarantees `ctx` is a valid pointer to the `RustFuzzTestAdapter`
    // created by `construct_adapter_callback`.
    let adapter = unsafe { &*(ctx as *const RustFuzzTestAdapter) };
    // SAFETY: The engine guarantees `origin` is a valid `FuzzTestInputHandle` pointing to
    // a heap-allocated `GenericCorpusValue` managed by the framework.
    let origin_ref = unsafe { &*(origin.0 as *const GenericCorpusValue) };
    // SAFETY: The engine guarantees `other` is a valid `FuzzTestInputHandle` pointing to
    // a heap-allocated `GenericCorpusValue` managed by the framework.
    let other_ref = unsafe { &*(other.0 as *const GenericCorpusValue) };
    // SAFETY: The engine guarantees `sink` is a valid pointer to `FuzzTestInputSink`.
    let mut safe_sink = unsafe { InputSink::from_raw(sink) };
    adapter.cross_over(origin_ref, other_ref, &mut safe_sink);
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
///   managed by the framework.
/// * `sink` is a valid pointer to `FuzzTestBytesSink`.
pub unsafe extern "C" fn serialize_input_metadata_callback(
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
    adapter.serialize_input_metadata(input_ref, &mut safe_sink);
}

/// # Safety
///
/// The caller must ensure that:
/// * `ctx` is a valid pointer to the `RustFuzzTestAdapter` created by `construct_adapter_callback`.
/// * `metadata` is a valid pointer to `FuzzTestBytesView` containing serialized input metadata.
/// * `input` is a valid `FuzzTestInputHandle` pointing to a heap-allocated `GenericCorpusValue`
///   managed by the framework, and the engine guarantees exclusive access to it for the call duration.
pub unsafe extern "C" fn update_input_metadata_callback(
    ctx: *mut engine_ffi::FuzzTestAdapterCtx,
    metadata: *const engine_ffi::FuzzTestBytesView,
    input: engine_ffi::FuzzTestInputHandle,
) {
    // SAFETY: The engine guarantees `ctx` is a valid pointer to the `RustFuzzTestAdapter`
    // created by `construct_adapter_callback`.
    let adapter = unsafe { &*(ctx as *const RustFuzzTestAdapter) };
    // SAFETY: The engine guarantees `metadata` is a valid pointer to `FuzzTestBytesView`
    // containing serialized input metadata.
    let bytes = unsafe { &*(*metadata).to_bytes() };
    // SAFETY: The engine guarantees `input` is a valid `FuzzTestInputHandle` pointing to
    // a heap-allocated `GenericCorpusValue` managed by the framework, and provides exclusive
    // access to it.
    let input_ref = unsafe { &mut *(input.0 as *mut GenericCorpusValue) };
    adapter.update_input_metadata(bytes, input_ref);
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

pub fn run_smoke_test(fuzztest: &dyn FuzzTest) {
    let start_time = std::time::Instant::now();

    // TODO(the-shank): these should be configurable externally.
    let smoke_test_duration = std::time::Duration::from_secs(1);
    let only_shrink = false;

    // TODO(the-shank): the rng seed should be configurable
    let mut rng = rand::rng();

    let mut generic_corpus_value = fuzztest
        .domains()
        .init(&mut rng)
        .expect("domain initialization should succeed to provide an initial corpus value");

    let result = fuzztest.execute(&generic_corpus_value);
    // DISCUSS: probably need a more "googletest" approach to handling the result here?
    assert!(result);

    while start_time.elapsed() < smoke_test_duration {
        fuzztest
            .domains()
            .mutate(&mut generic_corpus_value, &mut rng, only_shrink)
            .expect("domain mutation should succeed");
        let result = fuzztest.execute(&generic_corpus_value);
        // DISCUSS: probably need a more "googletest" approach to handling the result here?
        assert!(result);
    }
}

pub enum WorkerStatus {
    Success,
    Failure,
}

/// Processes and executes a fuzz test using the provided [`RustFuzzTestAdapterManager`].
///
/// This function serves as the primary entry point for running a fuzz test. It manages test
/// execution across two operational modes:
///
/// 1. Worker Mode: Registers signal/sanitizer crash handlers and attempts to hand off execution to
///    the external fuzzing engine (e.g., Centipede) via [`maybe_run_as_worker`].
///    - If the binary was spawned as a worker process by the fuzzing engine, control remains in the
///      engine loop until complete.
///    - Returns cleanly on [`WorkerStatus::Success`], or panics on [`WorkerStatus::Failure`] to
///      signal test failure to the harness.
/// 2. Smoke Test Mode: If worker mode is not active (e.g., during standard `blaze test` or
///    `cargo test` unit test runs), falls back to executing a short local smoke test using sample
///    inputs and mutation iterations to verify property function sanity.
pub fn process(manager: RustFuzzTestAdapterManager) {
    super::crash_handler::register_crash_handler();

    // box it to get a stable heap address.
    let manager = Box::new(manager);

    if let Some(status) = maybe_run_as_worker(&manager) {
        match status {
            WorkerStatus::Success => {
                // do nothing, the harness would continue to the next test
                return;
            }
            WorkerStatus::Failure => {
                std::process::exit(1);
            }
        }
    }

    // worker mode was not run -- determine what to do next.
    match options::determine_execution_action(Some(manager.test_name)) {
        ExecutionAction::Standalone(centipede_args) => {
            let status = run_standalone_mode(&manager, centipede_args);
            if status == engine_ffi::FuzzTestControllerStatus::Failure {
                panic!("FuzzTest controller reported failure");
            }
        }
        ExecutionAction::ReplayAllCrashes { args, list_file } => {
            let status = run_standalone_mode(&manager, args);
            if status == engine_ffi::FuzzTestControllerStatus::Failure {
                panic!("FuzzTest controller reported failure");
            }

            // Now read the file and replay each crash
            if let Ok(contents) = std::fs::read_to_string(list_file.path()) {
                let options = options::get_fuzztest_options();
                for crash_id in contents.lines() {
                    let crash_id = crash_id.trim();
                    if crash_id.is_empty() {
                        continue;
                    }
                    let replay_mode =
                        options::ExecutionMode::ReplayCrash(options::ReplayCrashOptions {
                            replay_id: crash_id.to_string(),
                        });
                    if let Ok(Some(replay_args)) = CentipedeArgs::from_execution_mode(
                        &replay_mode,
                        options,
                        Some(manager.test_name),
                        None,
                    ) {
                        // We ignore the result here because replaying a crash is expected to fail
                        // (report failure). We want to continue replaying other crashes.
                        let _ = run_standalone_mode(&manager, replay_args);
                    }
                }
            }
        }
        ExecutionAction::SmokeTest => {
            let fuzz_test = manager.construct_fuzz_test();
            run_smoke_test(fuzz_test.as_ref());
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
/// - `None`: Worker mode was not requested (`kFuzzTestWorkerNotRequired`). The caller should fall
///   back to standalone smoke-test execution.
fn maybe_run_as_worker(manager: &RustFuzzTestAdapterManager) -> Option<WorkerStatus> {
    let ffi_manager = make_ffi_manager(manager);

    // SAFETY: `manager` is a valid heap-allocated `RustFuzzTestAdapterManager`,
    // and `ffi_manager` contains valid C-compatible function pointer callbacks.
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
