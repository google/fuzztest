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
    // SAFETY: `has_emit_coverage_features` returned `true` on this thread, and `feedback` stays
    // borrowed until the call returns. Its safety-usable invariant then allows the first
    // requirement of `SanCovRuntimeEmitFeatures`: foreign code may call `EmitCoverageFeatures`
    // on this thread, one call at a time, with the `ctx` of `feedback` and a pointer to a valid
    // view.
    //
    // TODO(b/586877694): enforce the second requirement, which the next CL does with a lock.
    // Nothing enforces it here, as before this CL: the worker meets it by calling this crate
    // from engine callbacks only, which run one at a time.
    unsafe { SanCovRuntimeEmitFeatures(feedback) };
}

unsafe extern "C" {
    pub safe fn SanCovRuntimeClearCoverage(full_clear: bool);

    pub safe fn SanCovRuntimeGetCoverage(reject_input: bool) -> SanCovRuntimeRawFeatureParts;

    pub safe fn SanCovRuntimePostProcessCoverage(reject_input: bool);

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

    #[gtest]
    fn should_collect_features_from_sancov_callback() {
        SanCovRuntimeClearCoverage(true);

        __sanitizer_cov_trace_const_cmp1(1, 1);

        let features = SanCovRuntimeGetCoverage(false);
        expect_false!(features.ptr.is_null());
        expect_gt!(features.size, 0);
    }

    #[gtest]
    fn should_not_collect_features_from_empty_user_code() {
        SanCovRuntimeClearCoverage(true);

        // An execution where sancov hooks such as
        // `__sanitizer_cov_trace_const_cmp1` are not called.

        let features = SanCovRuntimeGetCoverage(false);
        expect_false!(features.ptr.is_null());
        expect_eq!(features.size, 0);
    }

    #[gtest]
    fn should_collect_features_from_user_code() {
        let x = std::env::args().count();

        SanCovRuntimeClearCoverage(true);

        {
            // An LLVM trace cmp callback is expected to be instrumented here.
            if x == 2 {
                std::hint::black_box(2); // To prevent dead code elimination.
            }
        }

        let features = SanCovRuntimeGetCoverage(false);
        expect_false!(features.ptr.is_null());
        expect_gt!(features.size, 0);
    }
}
