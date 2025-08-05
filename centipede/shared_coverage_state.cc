// Copyright 2022 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./centipede/shared_coverage_state.h"

#include <cstdlib>

#include "absl/base/nullability.h"
#include "./centipede/feature.h"
#include "./centipede/runner_interface.h"

namespace fuzztest::internal {

SharedCoverageState shared_coverage_state __attribute__((init_priority(150)));

// We use __thread instead of thread_local so that the compiler warns if
// the initializer for `tls` is not a constant expression.
// `tls` thus must not have a CTOR.
// This avoids calls to __tls_init() in hot functions that use `tls`.
__thread ThreadLocalRunnerState tls;

void MaybeAddFeature(feature_t feature) {
  if (!shared_coverage_state.run_time_flags.skip_seen_features) {
    shared_coverage_state.g_features.push_back(feature);
  } else if (!shared_coverage_state.seen_features.get(feature)) {
    shared_coverage_state.g_features.push_back(feature);
    shared_coverage_state.seen_features.set(feature);
  }
}

void PrepareSharedCoverage(bool full_clear) {
  if (!full_clear) return;
  if (shared_coverage_state.run_time_flags.use_cmp_features) {
    shared_coverage_state.cmp_eq_set.ForEachNonZeroBit([](size_t idx) {});
    shared_coverage_state.cmp_moddiff_set.ForEachNonZeroBit([](size_t idx) {});
    shared_coverage_state.cmp_hamming_set.ForEachNonZeroBit([](size_t idx) {});
    shared_coverage_state.cmp_difflog_set.ForEachNonZeroBit([](size_t idx) {});
  }
}

void PostProcessSharedCoverage() {
  // Convert cmp bit set to features.
  if (shared_coverage_state.run_time_flags.use_cmp_features) {
    shared_coverage_state.cmp_eq_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCMPEq.ConvertToMe(idx));
    });
    shared_coverage_state.cmp_moddiff_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCMPModDiff.ConvertToMe(idx));
    });
    shared_coverage_state.cmp_hamming_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCMPHamming.ConvertToMe(idx));
    });
    shared_coverage_state.cmp_difflog_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCMPDiffLog.ConvertToMe(idx));
    });
  }
}

extern "C" __attribute__((weak)) const char *absl_nullable
CentipedeGetRunnerFlags() {
  if (const char *runner_flags_env = getenv("CENTIPEDE_RUNNER_FLAGS"))
    return strdup(runner_flags_env);
  return nullptr;
}

}  // namespace fuzztest::internal
