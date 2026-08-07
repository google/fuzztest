#![deny(clippy::absolute_paths)]
#![deny(unused_imports)]

pub mod engine_ffi;

use std::marker::PhantomData;

#[allow(improper_ctypes)]
unsafe extern "C" {
    fn SanCovRuntimeSetUpCoverageDomains(
        registry: *const engine_ffi::FuzzTestCoverageDomainRegistry,
    ) -> usize;

    fn SanCovRuntimeEmitFeatures(sink: *const engine_ffi::FuzzTestFeedbackSink);
}

/// A zero-sized witness token proving that a test is currently executing.
///
/// Some of the methods on FuzzTestDiagnosticSink require that they are called only if the engine is
/// calling `Execute` callback of FuzzTestAdapter, which includes:
///
/// * `emit_finding`
///
/// The methods receiving this type can safely assume that the `Execute` callback is active because
/// the caller ensures this by creating this type.
pub struct ExecuteContext {
    _private: PhantomData<()>,
}

impl ExecuteContext {
    /// Creates a new execution context.
    ///
    /// # Safety
    ///
    /// * The caller must ensure that it is in the `Execute` callback of FuzzTestAdapter.
    pub unsafe fn new() -> Self {
        Self { _private: PhantomData }
    }
}

#[derive(Clone)]
pub struct DiagnosticSink {
    raw: engine_ffi::FuzzTestDiagnosticSink,
}

impl DiagnosticSink {
    /// Creates a safe wrapper from a pointer to `FuzzTestDiagnosticSink`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// * `raw` is a non-null, properly aligned pointer to a valid `FuzzTestDiagnosticSink`.
    /// * `(*raw).ctx` is a valid context pointer.
    /// * The sink and its context remain valid for the duration of `DiagnosticSink`'s usage
    ///   (guaranteed by the engine until `FreeCtx` is called on the adapter).
    pub unsafe fn from_raw(raw: *const engine_ffi::FuzzTestDiagnosticSink) -> Self {
        // SAFETY: Caller guarantees `raw` is a valid pointer to `FuzzTestDiagnosticSink`.
        let raw_sink = unsafe { *raw };
        Self { raw: raw_sink }
    }

    /// Emits an unrecoverable error message to the underlying diagnostic sink.
    pub fn emit_error(&self, message: &str) {
        let emit = self.raw.emit_error.expect("EmitError is required by ABI");
        let view = engine_ffi::FuzzTestBytesView::from_bytes(message.as_bytes());
        // SAFETY: The presence of `self` guarantees that the context of the underlying
        // `FuzzTestDiagnosticSink` remains live for the duration of this sink.
        unsafe {
            emit(self.raw.ctx, &view);
        }
    }

    /// Emits a warning message to the underlying diagnostic sink.
    pub fn emit_warning(&self, message: &str) {
        let emit = self.raw.emit_warning.expect("EmitWarning is required by ABI");
        let view = engine_ffi::FuzzTestBytesView::from_bytes(message.as_bytes());
        // SAFETY: The presence of `self` guarantees that the context of the underlying
        // `FuzzTestDiagnosticSink` remains live for the duration of this sink.
        unsafe {
            emit(self.raw.ctx, &view);
        }
    }

    /// Emits a test finding (e.g., a crash or bug) to the underlying diagnostic sink.
    ///
    /// This must only be called during test execution, which is guaranteed by the
    /// [`ExecuteContext`] token.
    pub fn emit_finding(&self, _token: &ExecuteContext, description: &str, signature: &str) {
        let emit = self.raw.emit_finding.expect("EmitFinding is required by ABI");
        let desc_view = engine_ffi::FuzzTestBytesView::from_bytes(description.as_bytes());
        let sig_view = engine_ffi::FuzzTestBytesView::from_bytes(signature.as_bytes());
        // SAFETY: The presence of `self` guarantees that the context of the underlying
        // `FuzzTestDiagnosticSink` remains live for the duration of this sink.
        // The witness `_token` further proves execution is currently within the `Execute` callback.
        unsafe {
            emit(self.raw.ctx, &desc_view, &sig_view);
        }
    }
}

pub struct BytesSink {
    raw: engine_ffi::FuzzTestBytesSink,
}

impl BytesSink {
    /// Creates a safe wrapper from a pointer to `FuzzTestBytesSink`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// * `raw` is a non-null, properly aligned pointer to a valid `FuzzTestBytesSink`.
    /// * `(*raw).ctx` is a valid context pointer.
    /// * The sink and its context remain valid for the duration of `BytesSink`'s usage
    ///   (guaranteed by the engine until `FreeCtx` is called on the adapter).
    pub unsafe fn from_raw(raw: *const engine_ffi::FuzzTestBytesSink) -> Self {
        // SAFETY: Caller guarantees `raw` is a valid pointer to `FuzzTestBytesSink`.
        let raw_sink = unsafe { *raw };
        Self { raw: raw_sink }
    }

    /// Emits a byte slice to the underlying bytes sink.
    ///
    /// Multiple calls to this function will concatenate the emitted bytes.
    pub fn emit(&mut self, bytes: &[u8]) {
        let emit = self.raw.emit.expect("Emit is required by ABI");
        let view = engine_ffi::FuzzTestBytesView::from_bytes(bytes);
        // SAFETY: The presence of `self` guarantees `from_raw` was called with a valid context
        // pointer (`self.raw.ctx`) that remains live for the duration of this call.
        unsafe {
            emit(self.raw.ctx, &view);
        }
    }
}

pub struct InputSink {
    raw: engine_ffi::FuzzTestInputSink,
}

impl InputSink {
    /// Creates a safe wrapper from a pointer to `FuzzTestInputSink`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// * `raw` is a non-null, properly aligned pointer to a valid `FuzzTestInputSink`.
    /// * `(*raw).ctx` is a valid context pointer.
    /// * The sink and its context remain valid for the duration of `InputSink`'s usage
    ///   (guaranteed by the engine until `FreeCtx` is called on the adapter).
    pub unsafe fn from_raw(raw: *const engine_ffi::FuzzTestInputSink) -> Self {
        // SAFETY: Caller guarantees `raw` is a valid pointer to `FuzzTestInputSink`.
        let raw_sink = unsafe { *raw };
        Self { raw: raw_sink }
    }

    /// Emits a test input handle to the underlying input sink.
    ///
    /// This function transfers ownership of the input represented by the handle
    /// to the engine. The engine is responsible for freeing it.
    pub fn emit(&mut self, input: engine_ffi::FuzzTestInputHandle) {
        let emit = self.raw.emit.expect("Emit is required by ABI");
        // SAFETY: The presence of `self` guarantees `from_raw` was called with a valid context
        // pointer (`self.raw.ctx`) that remains live for the duration of this call.
        unsafe {
            emit(self.raw.ctx, input);
        }
    }
}

pub struct FeedbackSink {
    raw: engine_ffi::FuzzTestFeedbackSink,
}

impl FeedbackSink {
    /// Creates a safe wrapper from a pointer to `FuzzTestFeedbackSink`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// * `raw` is a non-null, properly aligned pointer to a valid `FuzzTestFeedbackSink`.
    /// * `(*raw).ctx` is a valid context pointer.
    /// * The sink and its context remain valid for the duration of `FeedbackSink`'s usage
    ///   (guaranteed by the engine until `FreeCtx` is called on the adapter).
    pub unsafe fn from_raw(raw: *const engine_ffi::FuzzTestFeedbackSink) -> Self {
        // SAFETY: Caller guarantees `raw` is a valid pointer to `FuzzTestFeedbackSink`.
        let raw_sink = unsafe { *raw };
        Self { raw: raw_sink }
    }

    /// Emits execution coverage features to the underlying feedback sink.
    pub fn emit_coverage_features(&mut self, features: &[u64]) {
        let emit =
            self.raw.emit_coverage_features.expect("EmitCoverageFeatures is required by ABI");
        let view = engine_ffi::FuzzTestUint64sView::from_slice(features);
        // SAFETY: The presence of `self` guarantees `from_raw` was called with a valid context
        // pointer (`self.raw.ctx`) that remains live for the duration of this call.
        unsafe {
            emit(self.raw.ctx, &view);
        }
    }

    /// Emits SanitizerCoverage features.
    pub fn emit_sancov_features(&mut self) {
        // SAFETY: the sink pointer is guaranteed to be valid by the framework.
        unsafe { SanCovRuntimeEmitFeatures(&self.raw) };
    }
}

/// Information describing a coverage feature domain.
///
/// This is a high-level  wrapper for [`engine_ffi::FuzzTestCoverageDomain`],
/// which is the Rust representation of the C struct `FuzzTestCoverageDomain`
/// defined in `engine_abi.h` (the source of truth for the ABI).
///
/// Unlike the FFI representation which uses [`engine_ffi::FuzzTestBytesView`],
/// this type uses Rust slices (`&[u8]`) for safety and convenience. It can be
/// converted to the FFI representation using `From`/`Into`.
///
/// A coverage domain represents a logically independent feature namespace registered in
/// `CoverageDomainRegistry`. FuzzTest packs 64-bit coverage features into three parts:
/// * Bits 63..59 (5 bits): 5-bit domain ID (`domain_id`, up to 32 domains).
/// * Bits 58..32 (27 bits): Feature ID within the domain (`feature_id_bit_size` <= 27).
/// * Bits 31..0 (32 bits): Feature counter value (`counter_bit_size` <= 32).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoverageDomain<'a> {
    /// 5-bit unique domain identifier (must be < 32).
    pub domain_id: u8,
    /// Human-readable name of the domain for logging and debugging.
    pub name: &'a str,
    /// Number of bits used for feature IDs in this domain (must be <= 27).
    pub feature_id_bit_size: u8,
    /// Number of bits used for feature counter values in this domain (must be <= 32).
    pub counter_bit_size: u8,
}

impl<'a> From<CoverageDomain<'a>> for engine_ffi::FuzzTestCoverageDomain {
    fn from(domain: CoverageDomain<'a>) -> Self {
        Self {
            domain_id: domain.domain_id,
            name: engine_ffi::FuzzTestBytesView::from_bytes(domain.name.as_bytes()),
            feature_id_bit_size: domain.feature_id_bit_size,
            counter_bit_size: domain.counter_bit_size,
        }
    }
}

pub struct CoverageDomainRegistry {
    raw: engine_ffi::FuzzTestCoverageDomainRegistry,
}

impl CoverageDomainRegistry {
    /// Creates a safe wrapper from a pointer to `FuzzTestCoverageDomainRegistry`.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    /// * `raw` is a non-null, properly aligned pointer to a valid `FuzzTestCoverageDomainRegistry`.
    /// * `(*raw).ctx` is a valid context pointer.
    /// * The registry and its context remain valid for the duration of `CoverageDomainRegistry`'s usage
    ///   (guaranteed by the engine until `FreeCtx` is called on the adapter).
    pub unsafe fn from_raw(raw: *const engine_ffi::FuzzTestCoverageDomainRegistry) -> Self {
        // SAFETY: Caller guarantees `raw` is a valid pointer to `FuzzTestCoverageDomainRegistry`.
        let raw_registry = unsafe { *raw };
        Self { raw: raw_registry }
    }

    /// Sets up SanitizerCoverage domains.
    pub fn set_up_sancov_domains(&self) {
        // SAFETY: The registry pointer is guaranteed to be valid by the framework.
        unsafe { SanCovRuntimeSetUpCoverageDomains(&self.raw) };
    }
}
