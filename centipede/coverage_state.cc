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

#include "./centipede/coverage_state.h"

#include <atomic>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

#include "absl/base/nullability.h"
#include "./centipede/feature.h"
#include "./centipede/int_utils.h"
#include "./centipede/runner_result.h"
#include "./centipede/runner_utils.h"

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

CoverageState coverage_state __attribute__((init_priority(200)));

// We use __thread instead of thread_local so that the compiler warns if
// the initializer for `tls` is not a constant expression.
// `tls` thus must not have a CTOR.
// This avoids calls to __tls_init() in hot functions that use `tls`.
__thread ThreadLocalRunnerState tls;

extern "C" __attribute__((weak)) const char *absl_nullable
CentipedeGetRunnerFlags() {
  if (const char *runner_flags_env = getenv("CENTIPEDE_RUNNER_FLAGS"))
    return strdup(runner_flags_env);
  return nullptr;
}

__attribute__((noinline)) void CheckStackLimit(uintptr_t sp) {
  static std::atomic_flag stack_limit_exceeded = ATOMIC_FLAG_INIT;
  const size_t stack_limit = coverage_state.run_time_flags.stack_limit_kb.load()
                             << 10;
  // Check for the stack limit only if sp is inside the stack region.
  if (stack_limit > 0 && tls.stack_region_low &&
      tls.top_frame_sp - sp > stack_limit) {
    if (!coverage_state.test_started) return;
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

void CoverageState::CleanUpDetachedTls() {
  LockGuard lock(tls_list_mu);
  while (detached_tls_list) {
    ThreadLocalRunnerState *tls = detached_tls_list;
    detached_tls_list = detached_tls_list->next;
    delete tls;
  }
}

__attribute__((noinline))  // so that we see it in profile.
void PrepareCoverage(bool full_clear) {
  coverage_state.CleanUpDetachedTls();
  if (coverage_state.run_time_flags.path_level != 0) {
    coverage_state.ForEachTls([](ThreadLocalRunnerState &tls) {
      tls.path_ring_buffer.Reset(coverage_state.run_time_flags.path_level);
      tls.call_stack.Reset(coverage_state.run_time_flags.callstack_level);
      tls.lowest_sp = tls.top_frame_sp;
    });
  }
  {
    fuzztest::internal::LockGuard lock(
        coverage_state.execution_result_override_mu);
    if (coverage_state.execution_result_override != nullptr) {
      coverage_state.execution_result_override->ClearAndResize(0);
    }
  }
  if (!full_clear) return;
  coverage_state.ForEachTls([](ThreadLocalRunnerState &tls) {
    if (coverage_state.run_time_flags.use_auto_dictionary) {
      tls.cmp_trace2.Clear();
      tls.cmp_trace4.Clear();
      tls.cmp_trace8.Clear();
      tls.cmp_traceN.Clear();
    }
  });
  coverage_state.pc_counter_set.ForEachNonZeroByte(
      [](size_t idx, uint8_t value) {}, 0,
      coverage_state.actual_pc_counter_set_size_aligned);
  if (coverage_state.run_time_flags.use_dataflow_features)
    coverage_state.data_flow_feature_set.ForEachNonZeroBit([](size_t idx) {});
  if (coverage_state.run_time_flags.use_cmp_features) {
    coverage_state.cmp_feature_set.ForEachNonZeroBit([](size_t idx) {});
    coverage_state.cmp_eq_set.ForEachNonZeroBit([](size_t idx) {});
    coverage_state.cmp_moddiff_set.ForEachNonZeroBit([](size_t idx) {});
    coverage_state.cmp_hamming_set.ForEachNonZeroBit([](size_t idx) {});
    coverage_state.cmp_difflog_set.ForEachNonZeroBit([](size_t idx) {});
  }
  if (coverage_state.run_time_flags.path_level != 0)
    coverage_state.path_feature_set.ForEachNonZeroBit([](size_t idx) {});
  if (coverage_state.run_time_flags.callstack_level != 0)
    coverage_state.callstack_set.ForEachNonZeroBit([](size_t idx) {});
  for (auto *p = coverage_state.user_defined_begin;
       p != coverage_state.user_defined_end; ++p) {
    *p = 0;
  }
  coverage_state.sancov_objects.ClearInlineCounters();
  coverage_state.test_started = true;
}

static void MaybeAddFeature(feature_t feature) {
  if (!coverage_state.run_time_flags.skip_seen_features) {
    coverage_state.g_features.push_back(feature);
  } else if (!coverage_state.seen_features.get(feature)) {
    coverage_state.g_features.push_back(feature);
    coverage_state.seen_features.set(feature);
  }
}

// Adds a kPCs and/or k8bitCounters feature to `g_features` based on arguments.
// `idx` is a pc_index.
// `counter_value` (non-zero) is a counter value associated with that PC.
static void AddPcIndxedAndCounterToFeatures(size_t idx, uint8_t counter_value) {
  if (coverage_state.run_time_flags.use_pc_features) {
    MaybeAddFeature(feature_domains::kPCs.ConvertToMe(idx));
  }
  if (coverage_state.run_time_flags.use_counter_features) {
    MaybeAddFeature(feature_domains::k8bitCounters.ConvertToMe(
        Convert8bitCounterToNumber(idx, counter_value)));
  }
}
__attribute__((noinline))  // so that we see it in profile.
void PostProcessCoverage(int target_return_value) {
  coverage_state.g_features.clear();

  if (target_return_value == -1) return;

  // Convert counters to features.
  coverage_state.pc_counter_set.ForEachNonZeroByte(
      [](size_t idx, uint8_t value) {
        AddPcIndxedAndCounterToFeatures(idx, value);
      },
      0, coverage_state.actual_pc_counter_set_size_aligned);

  // Convert data flow bit set to features.
  if (coverage_state.run_time_flags.use_dataflow_features) {
    coverage_state.data_flow_feature_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kDataFlow.ConvertToMe(idx));
    });
  }

  // Convert cmp bit set to features.
  if (coverage_state.run_time_flags.use_cmp_features) {
    // TODO(kcc): remove cmp_feature_set.
    coverage_state.cmp_feature_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCMP.ConvertToMe(idx));
    });
    coverage_state.cmp_eq_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCMPEq.ConvertToMe(idx));
    });
    coverage_state.cmp_moddiff_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCMPModDiff.ConvertToMe(idx));
    });
    coverage_state.cmp_hamming_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCMPHamming.ConvertToMe(idx));
    });
    coverage_state.cmp_difflog_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCMPDiffLog.ConvertToMe(idx));
    });
  }

  // Convert path bit set to features.
  if (coverage_state.run_time_flags.path_level != 0) {
    coverage_state.path_feature_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kBoundedPath.ConvertToMe(idx));
    });
  }

  // Iterate all threads and get features from TLS data.
  coverage_state.ForEachTls([](ThreadLocalRunnerState &tls) {
    if (coverage_state.run_time_flags.callstack_level != 0) {
      RunnerCheck(tls.top_frame_sp >= tls.lowest_sp,
                  "bad values of tls.top_frame_sp and tls.lowest_sp");
      size_t sp_diff = tls.top_frame_sp - tls.lowest_sp;
      MaybeAddFeature(feature_domains::kCallStack.ConvertToMe(sp_diff));
    }
  });

  if (coverage_state.run_time_flags.callstack_level != 0) {
    coverage_state.callstack_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCallStack.ConvertToMe(idx));
    });
  }

  // Copy the features from __centipede_extra_features to g_features.
  // Zero features are ignored - we treat them as default (unset) values.
  for (auto *p = coverage_state.user_defined_begin;
       p != coverage_state.user_defined_end; ++p) {
    if (auto user_feature = *p) {
      // User domain ID is upper 32 bits
      feature_t user_domain_id = user_feature >> 32;
      // User feature ID is lower 32 bits.
      feature_t user_feature_id = user_feature & ((1ULL << 32) - 1);
      // There is no hard guarantee how many user domains are actually
      // available. If a user domain ID is out of range, alias it to an existing
      // domain. This is kinder than silently dropping the feature.
      user_domain_id %= std::size(feature_domains::kUserDomains);
      MaybeAddFeature(feature_domains::kUserDomains[user_domain_id].ConvertToMe(
          user_feature_id));
      *p = 0;  // cleanup for the next iteration.
    }
  }

  // Iterates all non-zero inline 8-bit counters, if they are present.
  // Calls AddPcIndxedAndCounterToFeatures on non-zero counters and zeroes them.
  if (coverage_state.run_time_flags.use_pc_features ||
      coverage_state.run_time_flags.use_counter_features) {
    coverage_state.sancov_objects.ForEachNonZeroInlineCounter(
        [](size_t idx, uint8_t counter_value) {
          AddPcIndxedAndCounterToFeatures(idx, counter_value);
        });
  }
}

void ThreadLocalRunnerState::TraceMemCmp(uintptr_t caller_pc, const uint8_t *s1,
                                         const uint8_t *s2, size_t n,
                                         bool is_equal) {
  if (coverage_state.run_time_flags.use_cmp_features) {
    const uintptr_t pc_offset =
        caller_pc - coverage_state.main_object.start_address;
    const uintptr_t hash =
        fuzztest::internal::Hash64Bits(pc_offset) ^ tls.path_ring_buffer.hash();
    const size_t lcp = LengthOfCommonPrefix(s1, s2, n);
    // lcp is a 6-bit number.
    coverage_state.cmp_feature_set.set((hash << 6) | lcp);
  }
  if (!is_equal && coverage_state.run_time_flags.use_auto_dictionary) {
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
  tls.call_stack.Reset(coverage_state.run_time_flags.callstack_level);
  tls.path_ring_buffer.Reset(coverage_state.run_time_flags.path_level);
  LockGuard lock(coverage_state.tls_list_mu);
  // Add myself to state.tls_list.
  auto *old_list = coverage_state.tls_list;
  tls.next = old_list;
  coverage_state.tls_list = &tls;
  if (old_list != nullptr) old_list->prev = &tls;
}

void ThreadLocalRunnerState::OnThreadStop() {
  LockGuard lock(coverage_state.tls_list_mu);
  // Remove myself from state.tls_list. The list never
  // becomes empty because the main thread does not call OnThreadStop().
  if (&tls == coverage_state.tls_list) {
    coverage_state.tls_list = tls.next;
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
  auto *old_list = coverage_state.detached_tls_list;
  detached_tls->next = old_list;
  coverage_state.detached_tls_list = detached_tls;
  if (old_list != nullptr) old_list->prev = detached_tls;
}

extern "C" void CentipedeSetFailureDescription(const char *description) {
  using fuzztest::internal::coverage_state;
  if (coverage_state.failure_description_path == nullptr) return;
  // Make sure that the write is atomic and only happens once.
  [[maybe_unused]] static int write_once = [=] {
    FILE *f = fopen(coverage_state.failure_description_path, "w");
    if (f == nullptr) {
      perror("FAILURE: fopen()");
      return 0;
    }
    const auto len = strlen(description);
    if (fwrite(description, 1, len, f) != len) {
      perror("FAILURE: fwrite()");
    }
    if (fflush(f) != 0) {
      perror("FAILURE: fflush()");
    }
    if (fclose(f) != 0) {
      perror("FAILURE: fclose()");
    }
    return 0;
  }();
}

}  // namespace fuzztest::internal
