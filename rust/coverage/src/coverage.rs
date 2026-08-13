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

unsafe extern "C" {
    pub safe fn SanCovRuntimeClearCoverage(full_clear: bool);

    pub safe fn SanCovRuntimeGetCoverage(reject_input: bool) -> SanCovRuntimeRawFeatureParts;

    pub safe fn SanCovRuntimePostProcessCoverage(reject_input: bool);

    // Exposed only for testing purposes.
    pub safe fn __sanitizer_cov_trace_const_cmp1(Arg1: u8, Arg2: u8);
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
