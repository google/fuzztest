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

//! Rust definitions of the FuzzTest engine ABI.
//!
//! The source of truth for the definitions in this file are these C headers:
//! - `engine_abi.h`
//! - `engine_worker_abi.h`
//! - `engine_controller_abi.h`
//!
//! The types are spelled so that the compiler checks what the headers say in comments. A
//! pointer that the engine lends for the duration of a callback is an `Option<&T>`. A struct
//! whose fields are only usable under a condition keeps them private, states the condition as
//! a safety invariant, and offers safe methods that rely on it.

use std::ffi::c_int;
use std::marker::PhantomData;
use std::marker::PhantomPinned;
use std::mem::MaybeUninit;
#[cfg(test)]
use std::ptr;
use std::slice;

/// Opaque handle for an in-memory input object used by the test.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FuzzTestInputHandle(pub usize);

/// A borrowed buffer of bytes.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct FuzzTestBytesView<'a> {
    // Safety invariant: `size` is 0, or `data` is non-null and points within a single allocated
    // object to `size` initialized bytes that are valid for reads and are not written to for `'a`,
    // with `size <= isize::MAX as usize`.
    data: *const u8,
    size: usize,
    _buffer: PhantomData<&'a [u8]>,
}

impl<'a> FuzzTestBytesView<'a> {
    pub fn from_bytes(bytes: &'a [u8]) -> Self {
        Self { data: bytes.as_ptr(), size: bytes.len(), _buffer: PhantomData }
    }

    pub fn as_bytes(&self) -> &'a [u8] {
        if self.size == 0 {
            return &[];
        }
        // SAFETY: `size` is not 0, so by the struct invariant `data` is non-null and points within
        // a single allocated object to `size` initialized bytes that are valid for reads and are
        // not written to for `'a`, with `size <= isize::MAX as usize`, and `u8` has alignment 1.
        unsafe { slice::from_raw_parts(self.data, self.size) }
    }
}

/// A borrowed array of byte buffers.
#[repr(C)]
pub struct FuzzTestBytesViews<'a> {
    // Safety invariant: `count` is 0, or `views` points to an array of `count` views that is
    // valid for reads and is not written to for `'a`.
    views: *const FuzzTestBytesView<'a>,
    count: usize,
    _views: PhantomData<&'a [FuzzTestBytesView<'a>]>,
}

impl<'a> FuzzTestBytesViews<'a> {
    pub fn from_slice(views: &'a [FuzzTestBytesView<'a>]) -> Self {
        Self { views: views.as_ptr(), count: views.len(), _views: PhantomData }
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
///
/// The fields are only used by the `diagnostics` module, whose `unsafe` functions state when
/// they may be called.
#[repr(C)]
pub struct FuzzTestDiagnosticSink {
    pub ctx: *mut FuzzTestDiagnosticSinkCtx,

    /// Emits an unrecoverable error with a human-readable `message`. Engine would
    /// propagate the error to the controller command when in the worker mode.
    pub emit_error: Option<
        unsafe extern "C" fn(ctx: *mut FuzzTestDiagnosticSinkCtx, message: &FuzzTestBytesView<'_>),
    >,

    /// Emits a warning with a human-readable `message`. Engine would log
    /// the warning and continue gracefully when in the worker mode.
    pub emit_warning: Option<
        unsafe extern "C" fn(ctx: *mut FuzzTestDiagnosticSinkCtx, message: &FuzzTestBytesView<'_>),
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
            description: &FuzzTestBytesView<'_>,
            signature: &FuzzTestBytesView<'_>,
        ),
    >,
}

#[repr(C)]
pub struct FuzzTestBytesSinkCtx {
    _opaque: (),
    _not_send_nor_sync: PhantomData<*mut ()>,
    _not_unpin: PhantomPinned,
}

/// Sink for bytes data.
#[repr(C)]
pub struct FuzzTestBytesSink {
    // Safety invariant: `emit` is null, or it may be called with `ctx` and a valid view for as
    // long as this value is borrowed.
    ctx: *mut FuzzTestBytesSinkCtx,
    emit:
        Option<unsafe extern "C" fn(ctx: *mut FuzzTestBytesSinkCtx, view: &FuzzTestBytesView<'_>)>,
}

impl FuzzTestBytesSink {
    /// Emits a byte buffer. Multiple emissions are concatenated.
    pub fn emit(&self, bytes: &[u8]) {
        let emit = self.emit.expect("Emit is required by ABI");
        // SAFETY: `emit` is not null, so by the struct invariant it may be called with `ctx`
        // while `self` is borrowed. The view borrows `bytes` for the duration of the call.
        unsafe { emit(self.ctx, &FuzzTestBytesView::from_bytes(bytes)) }
    }

    /// Creates a sink with a null context that forwards to `emit`.
    ///
    /// `emit` is a safe function, so it upholds the struct invariant whatever it is called with.
    #[cfg(test)]
    pub fn for_test(
        emit: extern "C" fn(ctx: *mut FuzzTestBytesSinkCtx, view: &FuzzTestBytesView<'_>),
    ) -> Self {
        Self { ctx: ptr::null_mut(), emit: Some(emit) }
    }
}

#[repr(C)]
pub struct FuzzTestInputSinkCtx {
    _opaque: (),
    _not_send_nor_sync: PhantomData<*mut ()>,
    _not_unpin: PhantomPinned,
}

/// Sink for seed inputs.
#[repr(C)]
pub struct FuzzTestInputSink {
    // Safety invariant: `emit` is null, or it may be called with `ctx` for as long as this
    // value is borrowed.
    ctx: *mut FuzzTestInputSinkCtx,
    emit: Option<unsafe extern "C" fn(ctx: *mut FuzzTestInputSinkCtx, input: FuzzTestInputHandle)>,
}

impl FuzzTestInputSink {
    /// Emits a test `input` to the engine. Engine would call
    /// `FuzzTestAdapter::FreeInput` on the emitted input after the engine is
    /// done with it.
    pub fn emit(&self, input: FuzzTestInputHandle) {
        let emit = self.emit.expect("Emit is required by ABI");
        // SAFETY: `emit` is not null, so by the struct invariant it may be called with `ctx`
        // while `self` is borrowed.
        unsafe { emit(self.ctx, input) }
    }

    /// Creates a sink with a null context that forwards to `emit`.
    ///
    /// `emit` is a safe function, so it upholds the struct invariant whatever it is called with.
    #[cfg(test)]
    pub fn for_test(
        emit: extern "C" fn(ctx: *mut FuzzTestInputSinkCtx, input: FuzzTestInputHandle),
    ) -> Self {
        Self { ctx: ptr::null_mut(), emit: Some(emit) }
    }
}

/// A borrowed array of 64-bit integers.
#[repr(C)]
pub struct FuzzTestUint64sView<'a> {
    // Safety invariant: `size` is 0, or `data` is non-null, aligned, and points within a single
    // allocated object to `size` initialized integers that are valid for reads and are not
    // written to for `'a`, with `size * size_of::<u64>() <= isize::MAX as usize`.
    data: *const u64,
    size: usize,
    _buffer: PhantomData<&'a [u64]>,
}

impl<'a> FuzzTestUint64sView<'a> {
    pub fn from_slice(slice: &'a [u64]) -> Self {
        Self { data: slice.as_ptr(), size: slice.len(), _buffer: PhantomData }
    }

    #[cfg(test)]
    pub fn as_slice(&self) -> &'a [u64] {
        if self.size == 0 {
            return &[];
        }
        // SAFETY: `size` is not 0, so by the struct invariant `data` is non-null, aligned, and
        // points within a single allocated object to `size` initialized integers that are valid
        // for reads and are not written to for `'a`, with `size * size_of::<u64>() <= isize::MAX
        // as usize`.
        unsafe { slice::from_raw_parts(self.data, self.size) }
    }
}

/// Constants for the layout of the coverage feature as a 64-bit unsigned
/// integer:
///
///   - Bits 63..59: 5-bit domain ID of the feature. Each domain is a logically independent feature
///     namespace registered in `FuzzTestAdapter::SetUpCoverageDomains`.
///   - Bits 58..32: 27-bit feature ID within the domain.
///   - Bits 31..0:  32-bit counter value of the feature.
pub struct FuzzTestCoverageFeatureLayout;

impl FuzzTestCoverageFeatureLayout {
    /// Bit offset of the feature counter value within a packed 64-bit coverage feature.
    pub const COUNTER_START_BIT: u32 = 0;
    /// Maximum number of bits used for the feature counter value.
    pub const COUNTER_BIT_SIZE: u32 = 32;
    /// Bit offset of the per-domain feature ID within a packed 64-bit coverage feature.
    pub const FEATURE_ID_START_BIT: u32 = 32;
    /// Maximum number of bits used for the feature ID within a domain.
    pub const FEATURE_ID_BIT_SIZE: u32 = 27;
    /// Bit offset of the coverage domain ID within a packed 64-bit coverage feature.
    pub const DOMAIN_ID_START_BIT: u32 = 59;
    /// Number of bits used for the coverage domain ID.
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
pub struct FuzzTestFeedbackSink {
    // Safety invariant: `emit_coverage_features` is null, or it may be called with `ctx` and a
    // valid view for as long as this value is borrowed.
    ctx: *mut FuzzTestFeedbackSinkCtx,
    emit_coverage_features: Option<
        unsafe extern "C" fn(ctx: *mut FuzzTestFeedbackSinkCtx, features: &FuzzTestUint64sView<'_>),
    >,
}

impl FuzzTestFeedbackSink {
    /// Emits an array of coverage features captured from the execution
    /// inside `Execute` call. See `FuzzTestCoverageFeatureLayout` for the feature
    /// layout.
    ///
    /// Multiple emissions are concatenated.
    pub fn emit_coverage_features(&self, features: &[u64]) {
        let emit = self.emit_coverage_features.expect("EmitCoverageFeatures is required by ABI");
        // SAFETY: `emit` is not null, so by the struct invariant it may be called with `ctx`
        // while `self` is borrowed. The view borrows `features` for the duration of the call.
        unsafe { emit(self.ctx, &FuzzTestUint64sView::from_slice(features)) }
    }

    /// Emits the SanitizerCoverage features of the execution.
    pub fn emit_sancov_features(&self) {
        // `SanCovRuntimeEmitFeatures` calls the callback without checking it.
        assert!(self.emit_coverage_features.is_some(), "EmitCoverageFeatures is required by ABI");
        // SAFETY: `SanCovRuntimeEmitFeatures` only uses the sink during the call. It calls
        // `emit_coverage_features`, which is not null, with `ctx` and a valid view, which the
        // struct invariant allows while `self` is borrowed.
        unsafe { SanCovRuntimeEmitFeatures(self) }
    }

    /// Creates a sink with a null context that forwards to `emit_coverage_features`.
    ///
    /// `emit_coverage_features` is a safe function, so it upholds the struct invariant whatever
    /// it is called with.
    #[cfg(test)]
    pub fn for_test(
        emit_coverage_features: extern "C" fn(
            ctx: *mut FuzzTestFeedbackSinkCtx,
            features: &FuzzTestUint64sView<'_>,
        ),
    ) -> Self {
        Self { ctx: ptr::null_mut(), emit_coverage_features: Some(emit_coverage_features) }
    }
}

/// Information of a coverage domain.
#[repr(C)]
pub struct FuzzTestCoverageDomain<'a> {
    /// 5-bit domain ID.
    pub domain_id: u8,
    /// Human-readable name of the domain for logging.
    pub name: FuzzTestBytesView<'a>,
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

/// Information describing a coverage feature domain.
///
/// This is a high-level wrapper for `FuzzTestCoverageDomain`, the Rust representation of the C
/// struct of the same name defined in `engine_abi.h` (the source of truth for the ABI).
///
/// Unlike the FFI representation, which uses `FuzzTestBytesView`, this type uses a Rust string
/// slice (`&str`) for safety and convenience. `CoverageDomainRegistry::register` takes it.
///
/// A coverage domain represents a logically independent feature namespace registered in
/// `CoverageDomainRegistry`. FuzzTest packs 64-bit coverage features into three parts:
/// * Bits 63..59 (5 bits): 5-bit domain ID (`domain_id`, up to 32 domains).
/// * Bits 58..32 (27 bits): Feature ID within the domain (`feature_id_bit_size` <= 27).
/// * Bits 31..0 (32 bits): Feature counter value (`counter_bit_size` <= 32).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoverageDomain<'name> {
    /// 5-bit unique domain identifier (must be < 32).
    pub domain_id: u8,
    /// Human-readable name of the domain for logging and debugging.
    pub name: &'name str,
    /// Number of bits used for feature IDs in this domain (must be <= 27).
    pub feature_id_bit_size: u8,
    /// Number of bits used for feature counter values in this domain (must be <= 32).
    pub counter_bit_size: u8,
}

/// Registry of the coverage domains of a test.
#[repr(C)]
pub struct FuzzTestCoverageDomainRegistry {
    // Safety invariant: `register` is null, or it may be called with `ctx` and a valid domain
    // for as long as this value is borrowed. A domain is valid if its name is valid for the
    // call and its numbers are within the ranges of `FuzzTestCoverageFeatureLayout`.
    ctx: *mut FuzzTestDomainRegistryCtx,
    register: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestDomainRegistryCtx,
            domain: &FuzzTestCoverageDomain<'_>,
        ),
    >,
}

impl FuzzTestCoverageDomainRegistry {
    /// Registers a coverage domain of the test.
    ///
    /// # Panics
    ///
    /// Panics if the ID of `domain` or one of its bit sizes does not fit in the layout of a
    /// coverage feature, see [`FuzzTestCoverageFeatureLayout`].
    pub fn register(&self, domain: CoverageDomain<'_>) {
        assert!(
            u32::from(domain.domain_id) < (1 << FuzzTestCoverageFeatureLayout::DOMAIN_ID_BIT_SIZE),
            "the domain ID {} does not fit in {} bits",
            domain.domain_id,
            FuzzTestCoverageFeatureLayout::DOMAIN_ID_BIT_SIZE
        );
        assert!(
            u32::from(domain.feature_id_bit_size)
                <= FuzzTestCoverageFeatureLayout::FEATURE_ID_BIT_SIZE,
            "the feature ID bit size {} is larger than {}",
            domain.feature_id_bit_size,
            FuzzTestCoverageFeatureLayout::FEATURE_ID_BIT_SIZE
        );
        assert!(
            u32::from(domain.counter_bit_size) <= FuzzTestCoverageFeatureLayout::COUNTER_BIT_SIZE,
            "the counter bit size {} is larger than {}",
            domain.counter_bit_size,
            FuzzTestCoverageFeatureLayout::COUNTER_BIT_SIZE
        );
        let register = self.register.expect("Register is required by ABI");
        let domain = FuzzTestCoverageDomain {
            domain_id: domain.domain_id,
            name: FuzzTestBytesView::from_bytes(domain.name.as_bytes()),
            feature_id_bit_size: domain.feature_id_bit_size,
            counter_bit_size: domain.counter_bit_size,
        };
        // SAFETY: `register` is not null, so by the struct invariant it may be called with
        // `ctx` and a valid domain while `self` is borrowed. `domain` is valid: its numbers
        // were checked above, and its name borrows a `&str` for the duration of the call.
        unsafe { register(self.ctx, &domain) }
    }

    /// Sets up the SanitizerCoverage domains.
    pub fn set_up_sancov_domains(&self) {
        // `SanCovRuntimeSetUpCoverageDomains` calls the callback without checking it.
        assert!(self.register.is_some(), "Register is required by ABI");
        // SAFETY: `SanCovRuntimeSetUpCoverageDomains` only uses the registry during the call.
        // It calls `register`, which is not null, with `ctx` and a valid domain, which the
        // struct invariant allows while `self` is borrowed.
        unsafe { SanCovRuntimeSetUpCoverageDomains(self) };
    }

    /// Creates a registry with a null context that forwards to `register`.
    ///
    /// `register` is a safe function, so it upholds the struct invariant whatever it is called
    /// with.
    #[cfg(test)]
    pub fn for_test(
        register: extern "C" fn(
            ctx: *mut FuzzTestDomainRegistryCtx,
            domain: &FuzzTestCoverageDomain<'_>,
        ),
    ) -> Self {
        Self { ctx: ptr::null_mut(), register: Some(register) }
    }
}

#[repr(C)]
pub struct FuzzTestAdapterCtx {
    _opaque: (),
    _not_send_nor_sync: PhantomData<*mut ()>,
    _not_unpin: PhantomPinned,
}

/// The callbacks of a test adapter. `engine_abi.h` documents how the engine calls them.
#[repr(C)]
pub struct FuzzTestAdapter {
    pub ctx: *mut FuzzTestAdapterCtx,

    /// Sets up coverage domains using the domain `registry`.
    /// The domain registrations must be the same for the all the test adapters of
    /// the same test (identified by the test name and the binary).
    pub set_up_coverage_domains: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterCtx,
            registry: Option<&FuzzTestCoverageDomainRegistry>,
        ),
    >,

    /// [Optional] Emits any preset seed inputs of the test using `sink`.
    /// The output must be the same for the all the test adapters of the same test
    /// (identified by the test name and the binary).
    pub get_preset_seed_inputs: Option<
        unsafe extern "C" fn(ctx: *mut FuzzTestAdapterCtx, sink: Option<&FuzzTestInputSink>),
    >,

    /// Emits a randomly generated seed input using `sink`.
    pub get_random_seed_input: Option<
        unsafe extern "C" fn(ctx: *mut FuzzTestAdapterCtx, sink: Option<&FuzzTestInputSink>),
    >,

    /// Mutates from `origin`, and emits the mutant using `sink`. `shrink` != 0
    /// means to generate smaller mutant.
    ///
    /// It should not change the content/metadata of `origin`.
    pub mutate: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterCtx,
            origin: FuzzTestInputHandle,
            shrink: c_int,
            sink: Option<&FuzzTestInputSink>,
        ),
    >,

    /// [Optional] Performs cross-over mutation using `origin` and `other`, and
    /// emits the mutant using `sink`. `origin` and `other` may be the same input.
    ///
    /// It should not change the content/metadata of `origin` or `other`.
    pub cross_over: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterCtx,
            origin: FuzzTestInputHandle,
            other: FuzzTestInputHandle,
            sink: Option<&FuzzTestInputSink>,
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
            sink: Option<&FuzzTestFeedbackSink>,
        ),
    >,

    /// Serializes the test `input` content into bytes using `sink`.
    pub serialize_input_content: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterCtx,
            input: FuzzTestInputHandle,
            sink: Option<&FuzzTestBytesSink>,
        ),
    >,

    /// Deserializes the test `input` content from serialized `content` into
    /// a `FuzzTestInputHandle` using `sink`.
    pub deserialize_input_content: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterCtx,
            content: Option<&FuzzTestBytesView<'_>>,
            sink: Option<&FuzzTestInputSink>,
        ),
    >,

    /// [Optional] Serializes the test `input` metadata into bytes using `sink`.
    pub serialize_input_metadata: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterCtx,
            input: FuzzTestInputHandle,
            sink: Option<&FuzzTestBytesSink>,
        ),
    >,

    /// [Optional] Updates the test `input` metadata from serialized `metadata`.
    pub update_input_metadata: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterCtx,
            metadata: Option<&FuzzTestBytesView<'_>>,
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

/// The callbacks of a test adapter manager. `engine_abi.h` documents how the engine calls them.
#[repr(C)]
pub struct FuzzTestAdapterManager {
    pub ctx: *mut FuzzTestAdapterManagerCtx,

    /// [Optional] Emits the ID for the current binary.
    pub get_binary_id: Option<
        unsafe extern "C" fn(ctx: *mut FuzzTestAdapterManagerCtx, sink: Option<&FuzzTestBytesSink>),
    >,

    /// Emits the test name.
    pub get_test_name: Option<
        unsafe extern "C" fn(ctx: *mut FuzzTestAdapterManagerCtx, sink: Option<&FuzzTestBytesSink>),
    >,

    /// Constructs an adapter of the test into `adapter_out`. Any diagnostics
    /// happening during the construction or running the adapter should be emitted
    /// to `diagnostic_sink`. `diagnostic_sink` is guaranteed to live until
    /// `FreeCtx` is called on the adapter.
    pub construct_adapter: Option<
        unsafe extern "C" fn(
            ctx: *mut FuzzTestAdapterManagerCtx,
            diagnostic_sink: Option<&FuzzTestDiagnosticSink>,
            adapter_out: Option<&mut MaybeUninit<FuzzTestAdapter>>,
        ),
    >,
}

/// `kFuzzTestWorkerSuccess`: the test should finish with a success.
pub const WORKER_SUCCESS: c_int = 0;
/// `kFuzzTestWorkerFailure`: the test should finish with a failure.
pub const WORKER_FAILURE: c_int = 1;
/// `kFuzzTestWorkerNotRequired`: the test should continue with controller commands.
pub const WORKER_NOT_REQUIRED: c_int = 2;
/// `kFuzzTestControllerSuccess`.
pub const CONTROLLER_SUCCESS: c_int = 0;

// `improper_ctypes` flags the `PhantomPinned` marker of the opaque context structs, because its
// layout is unspecified. The marker is zero-sized, and the contexts are only used behind
// pointers.
#[allow(improper_ctypes)]
// SAFETY: `FuzzTestWorkerMaybeRun` and `FuzzTestControllerRun` are defined with C linkage by the
// `cc_deps` of this crate, with the signatures of `engine_worker_abi.h` and
// `engine_controller_abi.h`. The two `SanCovRuntime*` functions are defined with C linkage by
// `//third_party/googlefuzztest/centipede:sancov_runtime`, with the signatures of
// `sancov_runtime.h`. This crate does not depend on that library: a binary that calls them links
// it through `//third_party/googlefuzztest/rust/coverage`. A reference has the ABI of the non-null
// pointer that the C signature takes. The two status enums are received as `c_int`, so that a
// value this file does not list is not undefined behavior.
unsafe extern "C" {
    /// Try to run as a FuzzTest worker with `manager` if needed. Returns a `WORKER_*` value.
    ///
    /// `manager` and its context are only used during the call.
    pub fn FuzzTestWorkerMaybeRun(manager: &FuzzTestAdapterManager) -> c_int;

    /// Run the FuzzTest controller with `flags` and `manager`. Returns `CONTROLLER_SUCCESS` or
    /// a failure value.
    ///
    /// `manager` and `flags` are only used during the call.
    pub fn FuzzTestControllerRun(
        manager: &FuzzTestAdapterManager,
        flags: &FuzzTestBytesViews<'_>,
    ) -> c_int;

    // TODO(b/586877694): a later CL of this chain moves the two declarations below to `coverage`
    // with `# Safety` sections, states in `sancov_runtime.h` what the runtime does with the
    // struct, and serializes the calls into the runtime. Until then their callers rely on
    // `sancov_state.cc`, and nothing stops another thread from post-processing the coverage
    // during `SanCovRuntimeEmitFeatures`, as before this CL.
    fn SanCovRuntimeSetUpCoverageDomains(registry: &FuzzTestCoverageDomainRegistry) -> usize;

    fn SanCovRuntimeEmitFeatures(sink: &FuzzTestFeedbackSink);
}

#[cfg(test)]
mod tests {
    use super::*;
    use googletest::prelude::*;

    extern "C" fn ignore_domain(
        _ctx: *mut FuzzTestDomainRegistryCtx,
        _domain: &FuzzTestCoverageDomain<'_>,
    ) {
    }

    /// The largest values that a registry accepts.
    fn largest_domain() -> CoverageDomain<'static> {
        CoverageDomain {
            domain_id: 31,
            name: "domain",
            feature_id_bit_size: 27,
            counter_bit_size: 32,
        }
    }

    #[gtest]
    #[should_panic(expected = "the domain ID 32 does not fit in 5 bits")]
    fn register_refuses_a_domain_id_that_does_not_fit() {
        let registry = FuzzTestCoverageDomainRegistry::for_test(ignore_domain);

        registry.register(CoverageDomain { domain_id: 32, ..largest_domain() });
    }

    #[gtest]
    #[should_panic(expected = "the feature ID bit size 28 is larger than 27")]
    fn register_refuses_too_many_feature_id_bits() {
        let registry = FuzzTestCoverageDomainRegistry::for_test(ignore_domain);

        registry.register(CoverageDomain { feature_id_bit_size: 28, ..largest_domain() });
    }

    #[gtest]
    #[should_panic(expected = "the counter bit size 33 is larger than 32")]
    fn register_refuses_too_many_counter_bits() {
        let registry = FuzzTestCoverageDomainRegistry::for_test(ignore_domain);

        registry.register(CoverageDomain { counter_bit_size: 33, ..largest_domain() });
    }
}
