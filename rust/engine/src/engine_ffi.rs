// The source of truth for the FFI definitions in this file are these C++ header files:
// - engine_abi.h
// - engine_worker_abi.h
// - engine_controller_abi.h
// TODO(b/532255598): use crubit

use core::ffi::c_int;

use core::marker::PhantomData;
use core::marker::PhantomPinned;
use core::ptr;

// Opaque handles for in-memory input objects used by the test, which
// may be serialized/deserialized by the engine.
#[repr(transparent)]
pub struct FuzzTestInputHandle(pub usize);

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FuzzTestBytesView {
    pub data: *const u8,
    pub size: usize,
}

impl FuzzTestBytesView {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self { data: bytes.as_ptr(), size: bytes.len() }
    }

    pub fn to_bytes(&self) -> *const [u8] {
        if self.data.is_null() {
            &[]
        } else {
            ptr::slice_from_raw_parts(self.data, self.size)
        }
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FuzzTestBytesViews {
    pub views: *const FuzzTestBytesView,
    pub count: usize,
}

impl FuzzTestBytesViews {
    pub fn from_slice(views: &[FuzzTestBytesView]) -> Self {
        Self { views: views.as_ptr(), count: views.len() }
    }

    pub fn as_slice(&self) -> *const [FuzzTestBytesView] {
        if self.views.is_null() {
            &[]
        } else {
            ptr::slice_from_raw_parts(self.views, self.count)
        }
    }
}

#[repr(C)]
pub struct FuzzTestDiagnosticSinkCtx {
    _opaque: (),
    _not_send_nor_sync: PhantomData<*mut ()>,
    _not_unpin: PhantomPinned,
}

/// Sink for diagnostics during the setup and execution of the test
/// methods. Methods in this sink are async-safe and thread-safe.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FuzzTestDiagnosticSink {
    pub ctx: *mut FuzzTestDiagnosticSinkCtx,

    /// Emits an unrecoverable error with a human-readable `message`. Engine would
    /// propagate the error to the controller command when in the worker mode.
    pub emit_error: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestDiagnosticSinkCtx,
            message: *const FuzzTestBytesView,
        ),
    >,

    /// Emits a warning with a human-readable `message`. Engine would log
    /// the warning and continue gracefully when in the worker mode.
    pub emit_warning: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestDiagnosticSinkCtx,
            message: *const FuzzTestBytesView,
        ),
    >,

    /// Emits a finding for running a test input within `Execute()` with a
    /// human-readable `description`, and `signature` for deduplication.
    ///
    /// Must not be called if the engine is not calling `Execute()`. If called
    /// multiple times within the same `Execute()` window, a random one would take
    /// effect.
    pub emit_finding: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestDiagnosticSinkCtx,
            description: *const FuzzTestBytesView,
            signature: *const FuzzTestBytesView,
        ),
    >,
}

// SAFETY: The engine guarantees that the diagnostic sink and its context are
// thread-safe and async-safe.
unsafe impl Send for FuzzTestDiagnosticSink {}
unsafe impl Sync for FuzzTestDiagnosticSink {}

#[repr(C)]
pub struct FuzzTestBytesSinkCtx {
    _opaque: (),
    _not_send_nor_sync: PhantomData<*mut ()>,
    _not_unpin: PhantomPinned,
}

/// Sink for bytes data.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FuzzTestBytesSink {
    pub ctx: *mut FuzzTestBytesSinkCtx,

    /// Emits a byte buffer. Multiple emissions are concatenated.
    pub emit: Option<
        unsafe extern "C" fn(ctx: *mut FuzzTestBytesSinkCtx, view: *const FuzzTestBytesView),
    >,
}

#[repr(C)]
pub struct FuzzTestInputSinkCtx {
    _opaque: (),
    _not_send_nor_sync: PhantomData<*mut ()>,
    _not_unpin: PhantomPinned,
}

/// Sink for seed inputs.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FuzzTestInputSink {
    pub ctx: *mut FuzzTestInputSinkCtx,

    /// Emits a test `input` to the engine. Engine would call
    /// `FuzzTestAdapter::FreeInput` on the emitted input after the engine is
    /// done with it.
    pub emit:
        Option<unsafe extern "C" fn(ctx: *mut FuzzTestInputSinkCtx, input: FuzzTestInputHandle)>,
}

#[repr(C)]
pub struct FuzzTestUint64sView {
    pub data: *const u64,
    pub size: usize,
}

impl FuzzTestUint64sView {
    pub fn from_slice(slice: &[u64]) -> Self {
        Self { data: slice.as_ptr(), size: slice.len() }
    }

    pub fn as_slice(&self) -> *const [u64] {
        if self.data.is_null() || self.size == 0 {
            &[]
        } else {
            ptr::slice_from_raw_parts(self.data, self.size)
        }
    }

    pub fn to_bytes(&self) -> *const [u8] {
        if self.data.is_null() {
            &[]
        } else {
            ptr::slice_from_raw_parts(
                self.data as *const u8,
                self.size * core::mem::size_of::<u64>(),
            )
        }
    }
}
/// Constants for the layout of the coverage feature as a 64-bit unsigned
/// integer:
///
///   - Bits 63..59: 5-bit domain ID of the feature. Each domain is a
///     logically independent feature namespace registered in
///     `FuzzTestAdapter::SetUpCoverageDomains`.
///   - Bits 58..32: 27-bit feature ID within the domain.
///   - Bits 31..0:  32-bit counter value of the feature.
///
pub struct FuzzTestCoverageFeatureLayout;

impl FuzzTestCoverageFeatureLayout {
    pub const COUNTER_START_BIT: u32 = 0;
    pub const COUNTER_BIT_SIZE: u32 = 32;
    pub const FEATURE_ID_START_BIT: u32 = 32;
    pub const FEATURE_ID_BIT_SIZE: u32 = 27;
    pub const DOMAIN_ID_START_BIT: u32 = 59;
    pub const DOMAIN_ID_BIT_SIZE: u32 = 5;
}

#[repr(C)]
pub struct FuzzTestFeedbackSinkCtx {
    _opaque: (),
    _not_send_nor_sync: PhantomData<*mut ()>,
    _not_unpin: PhantomPinned,
}

/// Sink for execution feedback.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct FuzzTestFeedbackSink {
    pub ctx: *mut FuzzTestFeedbackSinkCtx,

    /// Emits an array of coverage features captured from the execution
    /// inside `Execute` call. See `FuzzTestCoverageFeatureLayout` for the feature
    /// layout.
    ///
    /// Multiple emissions are concatenated.
    pub emit_coverage_features: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestFeedbackSinkCtx,
            features: *const FuzzTestUint64sView,
        ),
    >,
}

/// Information of a coverage domain.
#[repr(C)]
pub struct FuzzTestCoverageDomain {
    /// 5-bit domain ID.
    pub domain_id: u8,
    /// Human-readable name of the domain for logging.
    pub name: FuzzTestBytesView,
    /// Number of bits used for the feature IDs in this domain, must be <= 27.
    pub feature_id_bit_size: u8,
    /// Number of bits used for the counter values in this domain, must be <= 32.
    pub counter_bit_size: u8,
}

#[repr(C)]
pub struct FuzzTestDomainRegistryCtx {
    _opaque: (),
    _not_send_nor_sync: PhantomData<*mut ()>,
    _not_unpin: PhantomPinned,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct FuzzTestCoverageDomainRegistry {
    pub ctx: *mut FuzzTestDomainRegistryCtx,

    /// Registers a new coverage `domain`.
    pub register: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestDomainRegistryCtx,
            domain: *const FuzzTestCoverageDomain,
        ),
    >,
}

#[repr(C)]
pub struct FuzzTestAdapterCtx {
    _opaque: (),
    _not_send_nor_sync: PhantomData<*mut ()>,
    _not_unpin: PhantomPinned,
}

#[repr(C)]
pub struct FuzzTestAdapter {
    pub ctx: *mut FuzzTestAdapterCtx,

    /// Sets up coverage domains using the domain `registry`.
    /// The domain registrations must be the same for the all the test adapters of
    /// the same test (identified by the test name and the binary).
    pub set_up_coverage_domains: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterCtx,
            registry: *const FuzzTestCoverageDomainRegistry,
        ),
    >,

    /// [Optional] Emits any preset seed inputs of the test using `sink`.
    /// The output must be the same for the all the test adapters of the same test
    /// (identified by the test name and the binary).
    pub get_preset_seed_inputs:
        Option<unsafe extern "C" fn(ctx: *mut FuzzTestAdapterCtx, sink: *const FuzzTestInputSink)>,

    /// Emits a randomly generated seed input using `sink`.
    pub get_random_seed_input:
        Option<unsafe extern "C" fn(ctx: *mut FuzzTestAdapterCtx, sink: *const FuzzTestInputSink)>,

    /// Mutates from `origin`, and emits the mutant using `sink`. `shrink` != 0
    /// means to generate smaller mutant.
    ///
    /// It should not change the content/metadata of `origin`.
    pub mutate: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterCtx,
            origin: FuzzTestInputHandle,
            shrink: c_int,
            sink: *const FuzzTestInputSink,
        ),
    >,

    /// [Optional] Performs cross-over mutation using `origin` and `other`, and
    /// emits the mutant using `sink`.
    ///
    /// It should not change the content/metadata of `origin` or `other`.
    pub cross_over: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterCtx,
            origin: FuzzTestInputHandle,
            other: FuzzTestInputHandle,
            sink: *const FuzzTestInputSink,
        ),
    >,

    /// Executes `input` for testing and emits any feedback to `sink`.
    ///
    /// The `input` metadata may be updated by the adapter for further
    /// mutations. The `input` content, which affects the test behavior of
    /// `Execute()`, should not be changed.
    pub execute: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterCtx,
            input: FuzzTestInputHandle,
            sink: *const FuzzTestFeedbackSink,
        ),
    >,

    /// Serializes the test `input` content into bytes using `sink`.
    pub serialize_input_content: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterCtx,
            input: FuzzTestInputHandle,
            sink: *const FuzzTestBytesSink,
        ),
    >,

    /// Deserializes the test `input` content from serialized `content` into
    /// a `FuzzTestInputHandle` using `sink`.
    pub deserialize_input_content: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterCtx,
            content: *const FuzzTestBytesView,
            sink: *const FuzzTestInputSink,
        ),
    >,

    /// [Optional] Serializes the test `input` metadata into bytes using `sink`.
    pub serialize_input_metadata: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterCtx,
            input: FuzzTestInputHandle,
            sink: *const FuzzTestBytesSink,
        ),
    >,

    /// [Optional] Updates the test `input` metadata from serialized `metadata`.
    pub update_input_metadata: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterCtx,
            metadata: *const FuzzTestBytesView,
            input: FuzzTestInputHandle,
        ),
    >,

    /// Callback to run when the engine is done with `input`.
    pub free_input:
        Option<unsafe extern "C" fn(ctx: *mut FuzzTestAdapterCtx, input: FuzzTestInputHandle)>,

    /// Callback to run when the engine is done with `ctx` (and the adapter).
    pub free_ctx: Option<unsafe extern "C" fn(ctx: *mut FuzzTestAdapterCtx)>,
}

#[repr(C)]
pub struct FuzzTestAdapterManagerCtx {
    _opaque: (),
    _not_send_nor_sync: PhantomData<*mut ()>,
    _not_unpin: PhantomPinned,
}

#[repr(C)]
pub struct FuzzTestAdapterManager {
    pub ctx: *mut FuzzTestAdapterManagerCtx,

    /// [Optional] Emits the ID for the current binary.
    pub get_binary_id: Option<
        unsafe extern "C" fn(ctx: *mut FuzzTestAdapterManagerCtx, sink: *const FuzzTestBytesSink),
    >,

    /// Emits the test name.
    pub get_test_name: Option<
        unsafe extern "C" fn(ctx: *mut FuzzTestAdapterManagerCtx, sink: *const FuzzTestBytesSink),
    >,

    /// Constructs an adapter of the test into `adapter_out`. Any diagnostics
    /// happening during the construction or running the adapter should be emitted
    /// to `diagnostic_sink`. `diagnostic_sink` is guaranteed to live until
    /// `FreeCtx` is called on the adapter.
    pub construct_adapter: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterManagerCtx,
            diagnostic_sink: *const FuzzTestDiagnosticSink,
            adapter_out: *mut FuzzTestAdapter,
        ),
    >,
}

#[repr(i32)]
pub enum FuzzTestWorkerStatus {
    /// Test should finish with a success.
    Success = 0,
    /// Test should finish with a failure.
    Failure = 1,
    /// Test should continue with controller commands.
    NotRequired = 2,
}

#[derive(PartialEq, Eq)]
#[repr(i32)]
pub enum FuzzTestControllerStatus {
    Success = 0,
    Failure = 1,
}

#[allow(improper_ctypes)]
unsafe extern "C" {
    /// Try to run as a FuzzTest worker with `manager` if needed.
    pub fn FuzzTestWorkerMaybeRun(manager: *const FuzzTestAdapterManager) -> FuzzTestWorkerStatus;

    /// Returns whether the current process is running as a FuzzTest worker -
    /// non-zero means yes and zero means no. It can be called outside of tests.
    pub fn FuzzTestWorkerIsRequired() -> c_int;

    /// Run the FuzzTest controller with `flags` and `manager`.
    pub fn FuzzTestControllerRun(
        manager: *const FuzzTestAdapterManager,
        flags: *const FuzzTestBytesViews,
    ) -> FuzzTestControllerStatus;
}
