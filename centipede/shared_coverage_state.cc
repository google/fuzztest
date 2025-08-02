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

#include <atomic>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "absl/base/nullability.h"
#include "./centipede/feature.h"
#include "./centipede/flag_utils.h"
#include "./centipede/int_utils.h"
#include "./centipede/runner_interface.h"
#include "./centipede/runner_result.h"
#include "./centipede/runner_utils.h"

__attribute__((weak)) extern fuzztest::internal::feature_t
    __start___centipede_extra_features;
__attribute__((weak)) extern fuzztest::internal::feature_t
    __stop___centipede_extra_features;

namespace fuzztest::internal {
namespace {

// Returns the length of the common prefix of `s1` and `s2`, but not more
// than 63. I.e. the returned value is in [0, 64).
size_t LengthOfCommonPrefix(const void *s1, const void *s2, size_t n) {
  const auto *p1 = static_cast<const uint8_t *>(s1);
  const auto *p2 = static_cast<const uint8_t *>(s2);
  static constexpr size_t kMaxLen = 63;
  if (n > kMaxLen) n = kMaxLen;
  for (size_t i = 0; i < n; ++i) {
    if (p1[i] != p2[i]) return i;
  }
  return n;
}

class ThreadTerminationDetector {
 public:
  // A dummy method to trigger the construction and make sure that the
  // destructor will be called on the thread termination.
  __attribute__((optnone)) void EnsureAlive() {}

  ~ThreadTerminationDetector() { tls.OnThreadStop(); }
};

thread_local ThreadTerminationDetector termination_detector;

}  // namespace

SharedCoverageState shared_coverage_state __attribute__((init_priority(199)));

// We use __thread instead of thread_local so that the compiler warns if
// the initializer for `tls` is not a constant expression.
// `tls` thus must not have a CTOR.
// This avoids calls to __tls_init() in hot functions that use `tls`.
__thread ThreadLocalRunnerState tls;

void ThreadLocalRunnerState::TraceMemCmp(uintptr_t caller_pc, const uint8_t *s1,
                                         const uint8_t *s2, size_t n,
                                         bool is_equal) {
  if (run_time_flags.use_cmp_features) {
    const uintptr_t pc_offset =
        caller_pc - shared_coverage_state.main_object.start_address;
    const uintptr_t hash =
        fuzztest::internal::Hash64Bits(pc_offset) ^ tls.path_ring_buffer.hash();
    const size_t lcp = LengthOfCommonPrefix(s1, s2, n);
    // lcp is a 6-bit number.
    shared_coverage_state.cmp_feature_set.set((hash << 6) | lcp);
  }
  if (!is_equal && run_time_flags.use_auto_dictionary) {
    cmp_traceN.Capture(n, s1, s2);
  }
}

void ThreadLocalRunnerState::OnThreadStart() {
  termination_detector.EnsureAlive();
  tls.started = true;
  tls.lowest_sp = tls.top_frame_sp =
      reinterpret_cast<uintptr_t>(__builtin_frame_address(0));
  tls.stack_region_low = GetCurrentThreadStackRegionLow();
  if (tls.stack_region_low == 0) {
    fprintf(stderr,
            "Disabling stack limit check due to missing stack region info.\n");
  }
  tls.call_stack.Reset(run_time_flags.callstack_level);
  tls.path_ring_buffer.Reset(run_time_flags.path_level);
  LockGuard lock(shared_coverage_state.tls_list_mu);
  // Add myself to state.tls_list.
  auto *old_list = shared_coverage_state.tls_list;
  tls.next = old_list;
  shared_coverage_state.tls_list = &tls;
  if (old_list != nullptr) old_list->prev = &tls;
}

void ThreadLocalRunnerState::OnThreadStop() {
  LockGuard lock(shared_coverage_state.tls_list_mu);
  // Remove myself from state.tls_list. The list never
  // becomes empty because the main thread does not call OnThreadStop().
  if (&tls == shared_coverage_state.tls_list) {
    shared_coverage_state.tls_list = tls.next;
    tls.prev = nullptr;
  } else {
    auto *prev_tls = tls.prev;
    auto *next_tls = tls.next;
    prev_tls->next = next_tls;
    if (next_tls != nullptr) next_tls->prev = prev_tls;
  }
  tls.next = tls.prev = nullptr;
  if (tls.ignore) return;
  // Create a detached copy on heap and add it to detached_tls_list to
  // collect its coverage later.
  //
  // TODO(xinhaoyuan): Consider refactoring the list operations into class
  // methods instead of duplicating them.
  ThreadLocalRunnerState *detached_tls = new ThreadLocalRunnerState(tls);
  auto *old_list = shared_coverage_state.detached_tls_list;
  detached_tls->next = old_list;
  shared_coverage_state.detached_tls_list = detached_tls;
  if (old_list != nullptr) old_list->prev = detached_tls;
}

void SharedCoverageState::CleanUpDetachedTls() {
  LockGuard lock(tls_list_mu);
  ThreadLocalRunnerState *it_next = nullptr;
  for (auto *it = detached_tls_list; it; it = it_next) {
    it_next = it->next;
    delete it;
  }
  detached_tls_list = nullptr;
}

SharedCoverageState::~SharedCoverageState() {
  // Always clean up detached TLSs to avoid leakage.
  CleanUpDetachedTls();
}

void MaybeAddFeature(feature_t feature) {
  if (!run_time_flags.skip_seen_features) {
    shared_coverage_state.g_features.push_back(feature);
  } else if (!shared_coverage_state.seen_features.get(feature)) {
    shared_coverage_state.g_features.push_back(feature);
    shared_coverage_state.seen_features.set(feature);
  }
}

void PrepareSharedCoverage(bool full_clear) {
  if (!full_clear) return;
  if (run_time_flags.use_cmp_features) {
    shared_coverage_state.cmp_eq_set.ForEachNonZeroBit([](size_t idx) {});
    shared_coverage_state.cmp_moddiff_set.ForEachNonZeroBit([](size_t idx) {});
    shared_coverage_state.cmp_hamming_set.ForEachNonZeroBit([](size_t idx) {});
    shared_coverage_state.cmp_difflog_set.ForEachNonZeroBit([](size_t idx) {});
  }
}

void PostProcessSharedCoverage() {
  // Convert cmp bit set to features.
  if (run_time_flags.use_cmp_features) {
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

__attribute__((noinline)) void CheckStackLimit(uintptr_t sp) {
  static std::atomic_flag stack_limit_exceeded = ATOMIC_FLAG_INIT;
  const size_t stack_limit = run_time_flags.stack_limit_kb.load() << 10;
  // Check for the stack limit only if sp is inside the stack region.
  if (stack_limit > 0 && tls.stack_region_low &&
      tls.top_frame_sp - sp > stack_limit) {
    const bool test_not_running = shared_coverage_state.input_start_time == 0;
    if (test_not_running) return;
    if (stack_limit_exceeded.test_and_set()) return;
    fprintf(stderr,
            "========= Stack limit exceeded: %" PRIuPTR
            " > %zu"
            " (byte); aborting\n",
            tls.top_frame_sp - sp, stack_limit);
    CentipedeSetFailureDescription(
        fuzztest::internal::kExecutionFailureStackLimitExceeded.data());
    std::abort();
  }
}

extern "C" __attribute__((weak)) const char *absl_nullable
CentipedeGetRunnerFlags() {
  if (const char *runner_flags_env = getenv("CENTIPEDE_RUNNER_FLAGS"))
    return strdup(runner_flags_env);
  return nullptr;
}

}  // namespace fuzztest::internal
