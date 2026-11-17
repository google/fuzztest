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

use engine::{CoverageDomainRegistry, FeedbackSink};
use std::slice;
use std::sync::{Mutex, MutexGuard};

#[repr(C)]
pub struct SanCovRuntimeRawFeatureParts {
    // Safety invariant: The only way to receive this type is through `SanCovRuntimeGetCoverage()`
    // which guarantees that `ptr` always points to a valid slice of `size` elements.
    ptr: *const u64,
    size: usize,
}

impl SanCovRuntimeRawFeatureParts {
    /// # Safety
    ///
    /// Must not be held on when its data has to be mutated. For example, do not hold on to it
    /// when calling `SanCovRuntimeGetCoverage()`.
    pub unsafe fn as_slice(&self) -> &[u64] {
        // Safety: self ensures that `ptr` always points to a valid slice of `size` elements.
        unsafe { slice::from_raw_parts(self.ptr, self.size) }
    }
}

/// Serializes the calls of this crate into the SanitizerCoverage runtime. The runtime keeps the
/// coverage that it collects in process-wide state, and expects one thread at a time to process
/// it.
///
/// The lock does not cover the SanitizerCoverage hooks: instrumented code calls them on any
/// thread, also while the coverage is processed, as it does in a C++ fuzz test. In a build that
/// instruments this crate too, taking and releasing the lock is itself instrumented code, and
/// adds the same few features to every execution.
// Safety invariant: this crate calls `SanCovRuntimeClearCoverage`, `SanCovRuntimeGetCoverage`,
// `SanCovRuntimePostProcessCoverage` and `SanCovRuntimeEmitFeatures` only while it holds this
// lock. Their declarations are private to this module.
static RUNTIME: Mutex<()> = Mutex::new(());

/// Waits until no other thread is inside a call of this crate into the runtime.
///
/// # Safety-usable invariant
///
/// While the returned guard is alive, no other thread holds `RUNTIME`.
fn lock_runtime() -> MutexGuard<'static, ()> {
    // Outside the unit tests only foreign code runs while the lock is held, and it does not
    // panic, so the lock is not poisoned.
    RUNTIME.lock().expect("no code panics while it holds the SanCov runtime lock")
}

/// Clears the thread-local coverage data of the last execution, and all the coverage data
/// collected so far if `full_clear` is set.
pub(crate) fn prepare_coverage(full_clear: bool) {
    let _runtime = lock_runtime();
    // SAFETY: `_runtime` is alive until the call returns, so by the safety-usable invariant of
    // `lock_runtime` no other thread holds `RUNTIME`, and by the invariant of `RUNTIME` no other
    // thread is inside a call of this crate to one of the functions that the `# Safety` section
    // names. Nothing else in a Rust FuzzTest binary calls these functions: the engine does not
    // know about the SanitizerCoverage runtime, and the runtime starts no thread.
    unsafe { SanCovRuntimeClearCoverage(full_clear) }
}

/// Post-processes the collected coverage and returns the resulting features.
pub(crate) fn get_coverage(reject_input: bool) -> SanCovRuntimeRawFeatureParts {
    let _runtime = lock_runtime();
    // SAFETY: as in `prepare_coverage`.
    unsafe { SanCovRuntimeGetCoverage(reject_input) }
}

/// Post-processes the collected coverage, for `emit_coverage_features`.
pub(crate) fn post_process_coverage(reject_input: bool) {
    let _runtime = lock_runtime();
    // SAFETY: as in `prepare_coverage`.
    unsafe { SanCovRuntimePostProcessCoverage(reject_input) }
}

/// Registers the SanitizerCoverage domains with `registry`.
pub(crate) fn set_up_coverage_domains(registry: &CoverageDomainRegistry) {
    // The runtime calls `Register` without checking it.
    assert!(registry.has_register(), "Register is required by ABI");
    // SAFETY: `has_register` returned `true` on this thread, and `registry` stays borrowed until
    // the call returns. Its safety-usable invariant then allows what
    // `SanCovRuntimeSetUpCoverageDomains` requires: foreign code may call `Register` on this
    // thread, one call at a time, with the `ctx` of `registry` and a pointer to a valid domain.
    unsafe { SanCovRuntimeSetUpCoverageDomains(registry) };
}

/// Emits the post-processed SanitizerCoverage features into `feedback`.
pub(crate) fn emit_coverage_features(feedback: &FeedbackSink) {
    // The runtime calls `EmitCoverageFeatures` without checking it.
    assert!(feedback.has_emit_coverage_features(), "EmitCoverageFeatures is required by ABI");
    let _runtime = lock_runtime();
    // SAFETY: `has_emit_coverage_features` returned `true` on this thread, and `feedback` stays
    // borrowed until the call returns. Its safety-usable invariant then allows the first
    // requirement of `SanCovRuntimeEmitFeatures`: foreign code may call `EmitCoverageFeatures`
    // on this thread, one call at a time, with the `ctx` of `feedback` and a pointer to a valid
    // view.
    //
    // For the second requirement, `_runtime` is alive until the call returns, as in
    // `prepare_coverage`.
    unsafe { SanCovRuntimeEmitFeatures(feedback) };
}

// SAFETY: `:sancov_runtime` in `cc_deps` defines these functions with C linkage: the first three
// with the signatures of `centipede/sancov_runtime.h`, where `SanCovRuntimeRawFeatureParts` has
// the layout of the C struct of the same name, and the last one with the signature of the
// SanitizerCoverage interface. The last one is a SanitizerCoverage hook: instrumented code calls
// it at comparisons, on any thread, so a call from this crate does nothing that safe instrumented
// code does not do.
unsafe extern "C" {
    /// # Safety
    ///
    /// The caller must ensure that, until this function returns, no other thread runs this
    /// function, `SanCovRuntimeGetCoverage` or `SanCovRuntimePostProcessCoverage`: they rewrite
    /// the same counters, and the runtime does not lock them.
    fn SanCovRuntimeClearCoverage(full_clear: bool);

    /// # Safety
    ///
    /// The caller must ensure that, until this function returns, no other thread runs this
    /// function, `SanCovRuntimeClearCoverage`, `SanCovRuntimePostProcessCoverage` or
    /// `SanCovRuntimeEmitFeatures`: they rewrite the same counters and features, and the runtime
    /// does not lock them.
    fn SanCovRuntimeGetCoverage(reject_input: bool) -> SanCovRuntimeRawFeatureParts;

    /// # Safety
    ///
    /// The same as for `SanCovRuntimeGetCoverage`.
    fn SanCovRuntimePostProcessCoverage(reject_input: bool);

    // Exposed only for testing purposes.
    pub safe fn __sanitizer_cov_trace_const_cmp1(Arg1: u8, Arg2: u8);
}

// SAFETY: `:sancov_runtime` in `cc_deps` defines these functions with C linkage and the signatures
// of `centipede/sancov_runtime.h`. `CoverageDomainRegistry` and `FeedbackSink` are the `#[repr(C)]`
// types that `engine` declares for `FuzzTestCoverageDomainRegistry` and `FuzzTestFeedbackSink` of
// `centipede/engine_abi.h`, and a reference has the ABI of the non-null pointer that the C
// signature takes.
unsafe extern "C" {
    /// Registers the SanitizerCoverage domains with `registry`. Returns the next free domain ID.
    ///
    /// # Safety
    ///
    /// The caller must ensure that the `Register` callback of `registry` is set, and that until
    /// this function returns foreign code may call it on the calling thread, one call at a time,
    /// with the `ctx` of `registry` and a pointer to a valid domain, as defined on
    /// `CoverageDomainRegistry::has_register`.
    ///
    /// The runtime does nothing else with `registry`: it calls `Register` that way, and it does
    /// not keep `registry` (see `centipede/sancov_runtime.h`).
    // The lint cannot tell that the opaque context type of `engine` is only used behind a pointer.
    #[allow(improper_ctypes)]
    fn SanCovRuntimeSetUpCoverageDomains(registry: &CoverageDomainRegistry) -> usize;

    /// Emits the post-processed features into `sink`, then clears them.
    ///
    /// # Safety
    ///
    /// The caller must ensure that:
    ///
    /// * the `EmitCoverageFeatures` callback of `sink` is set, and until this function returns
    ///   foreign code may call it on the calling thread, one call at a time, with the `ctx` of
    ///   `sink` and a pointer to a valid view, as defined on
    ///   `FeedbackSink::has_emit_coverage_features`;
    /// * until this function returns, no other thread runs this function,
    ///   `SanCovRuntimeGetCoverage` or `SanCovRuntimePostProcessCoverage`: they rewrite the same
    ///   features, and the runtime does not lock them.
    ///
    /// The runtime does nothing else with `sink`: it calls `EmitCoverageFeatures` once, that
    /// way, and it does not keep `sink` (see `centipede/sancov_runtime.h`).
    // The lint cannot tell that the opaque context type of `engine` is only used behind a pointer.
    #[allow(improper_ctypes)]
    fn SanCovRuntimeEmitFeatures(sink: &FeedbackSink);
}

#[cfg(test)]
mod test {
    use super::*;
    use googletest::prelude::*;

    // These tests call the runtime directly, and hold `RUNTIME` from before the coverage is
    // cleared until it has been processed. The test binary is instrumented, so the lock code of
    // `prepare_coverage` and `get_coverage` would add features of its own between the two calls.

    #[gtest]
    fn should_collect_features_from_sancov_callback() {
        let _runtime = lock_runtime();
        // SAFETY: `_runtime` is alive until the end of the test, as in `prepare_coverage`.
        unsafe { SanCovRuntimeClearCoverage(true) };

        __sanitizer_cov_trace_const_cmp1(1, 1);

        // SAFETY: `_runtime` is alive until the end of the test, as in `prepare_coverage`.
        let features = unsafe { SanCovRuntimeGetCoverage(false) };
        expect_false!(features.ptr.is_null());
        expect_gt!(features.size, 0);
    }

    #[gtest]
    fn should_not_collect_features_from_empty_user_code() {
        let _runtime = lock_runtime();
        // SAFETY: `_runtime` is alive until the end of the test, as in `prepare_coverage`.
        unsafe { SanCovRuntimeClearCoverage(true) };

        // An execution where sancov hooks such as
        // `__sanitizer_cov_trace_const_cmp1` are not called.

        // SAFETY: `_runtime` is alive until the end of the test, as in `prepare_coverage`.
        let features = unsafe { SanCovRuntimeGetCoverage(false) };
        expect_false!(features.ptr.is_null());
        expect_eq!(features.size, 0);
    }

    #[gtest]
    fn should_collect_features_from_user_code() {
        let x = std::env::args().count();

        let _runtime = lock_runtime();
        // SAFETY: `_runtime` is alive until the end of the test, as in `prepare_coverage`.
        unsafe { SanCovRuntimeClearCoverage(true) };

        {
            // An LLVM trace cmp callback is expected to be instrumented here.
            if x == 2 {
                std::hint::black_box(2); // To prevent dead code elimination.
            }
        }

        // SAFETY: `_runtime` is alive until the end of the test, as in `prepare_coverage`.
        let features = unsafe { SanCovRuntimeGetCoverage(false) };
        expect_false!(features.ptr.is_null());
        expect_gt!(features.size, 0);
    }
}
