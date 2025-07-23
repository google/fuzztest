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

#include "./centipede/sancov_state.h"

#include <atomic>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "./centipede/feature.h"
#include "./centipede/flag_utils.h"
#include "./centipede/int_utils.h"
#include "./centipede/runner_interface.h"
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

SancovState sancov_state __attribute__((init_priority(199)));

// We use __thread instead of thread_local so that the compiler warns if
// the initializer for `tls` is not a constant expression.
// `tls` thus must not have a CTOR.
// This avoids calls to __tls_init() in hot functions that use `tls`.
__thread ThreadLocalSancovState tls;

void ThreadLocalSancovState::TraceMemCmp(uintptr_t caller_pc, const uint8_t *s1,
                                         const uint8_t *s2, size_t n,
                                         bool is_equal) {
  if (sancov_state.flags.use_cmp_features) {
    const uintptr_t pc_offset =
        caller_pc - sancov_state.main_object.start_address;
    const uintptr_t hash =
        fuzztest::internal::Hash64Bits(pc_offset) ^ tls.path_ring_buffer.hash();
    const size_t lcp = LengthOfCommonPrefix(s1, s2, n);
    // lcp is a 6-bit number.
    sancov_state.cmp_feature_set.set((hash << 6) | lcp);
  }
  if (!is_equal && sancov_state.flags.use_auto_dictionary) {
    cmp_traceN.Capture(n, s1, s2);
  }
}

void ThreadLocalSancovState::OnThreadStart() {
  termination_detector.EnsureAlive();
  tls.started = true;
  tls.lowest_sp = tls.top_frame_sp =
      reinterpret_cast<uintptr_t>(__builtin_frame_address(0));
  tls.stack_region_low = GetCurrentThreadStackRegionLow();
  if (tls.stack_region_low == 0) {
    fprintf(stderr,
            "Disabling stack limit check due to missing stack region info.\n");
  }
  tls.call_stack.Reset(sancov_state.flags.callstack_level);
  tls.path_ring_buffer.Reset(sancov_state.flags.path_level);
  LockGuard lock(sancov_state.tls_list_mu);
  // Add myself to state.tls_list.
  auto *old_list = sancov_state.tls_list;
  tls.next = old_list;
  sancov_state.tls_list = &tls;
  if (old_list != nullptr) old_list->prev = &tls;
}

void ThreadLocalSancovState::OnThreadStop() {
  LockGuard lock(sancov_state.tls_list_mu);
  // Remove myself from state.tls_list. The list never
  // becomes empty because the main thread does not call OnThreadStop().
  if (&tls == sancov_state.tls_list) {
    sancov_state.tls_list = tls.next;
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
  ThreadLocalSancovState *detached_tls = new ThreadLocalSancovState(tls);
  auto *old_list = sancov_state.detached_tls_list;
  detached_tls->next = old_list;
  sancov_state.detached_tls_list = detached_tls;
  if (old_list != nullptr) old_list->prev = detached_tls;
}

void SancovState::CleanUpDetachedTls() {
  LockGuard lock(tls_list_mu);
  ThreadLocalSancovState *it_next = nullptr;
  for (auto *it = detached_tls_list; it; it = it_next) {
    it_next = it->next;
    delete it;
  }
  detached_tls_list = nullptr;
}

SancovState::~SancovState() {
  // Always clean up detached TLSs to avoid leakage.
  CleanUpDetachedTls();
}

// Avoids the following situation:
// * weak implementations of sancov callbacks are given in the command line
//   before centipede.a.
// * linker sees them and decides to drop runner_sancov.o.
extern void RunnerSancov();
[[maybe_unused]] auto fake_reference_for_runner_sancov = &RunnerSancov;
// Same for runner_interceptor.cc.
extern void RunnerInterceptor();
[[maybe_unused]] auto fake_reference_for_runner_interceptor =
    &RunnerInterceptor;

void MaybeAddFeature(feature_t feature) {
  if (!sancov_state.flags.skip_seen_features) {
    sancov_state.g_features.push_back(feature);
  } else if (!sancov_state.seen_features.get(feature)) {
    sancov_state.g_features.push_back(feature);
    sancov_state.seen_features.set(feature);
  }
}

void PrepareTls() {
  sancov_state.CleanUpDetachedTls();
  if (sancov_state.flags.path_level != 0) {
    sancov_state.ForEachTls([](ThreadLocalSancovState &tls) {
      tls.path_ring_buffer.Reset(sancov_state.flags.path_level);
      tls.call_stack.Reset(sancov_state.flags.callstack_level);
      tls.lowest_sp = tls.top_frame_sp;
    });
  }
}

void PrepareSancov() {
  sancov_state.ForEachTls([](ThreadLocalSancovState &tls) {
    if (sancov_state.flags.use_auto_dictionary) {
      tls.cmp_trace2.Clear();
      tls.cmp_trace4.Clear();
      tls.cmp_trace8.Clear();
      tls.cmp_traceN.Clear();
    }
  });
  sancov_state.pc_counter_set.ForEachNonZeroByte(
      [](size_t idx, uint8_t value) {}, 0,
      sancov_state.actual_pc_counter_set_size_aligned);
  if (sancov_state.flags.use_dataflow_features)
    sancov_state.data_flow_feature_set.ForEachNonZeroBit([](size_t idx) {});
  if (sancov_state.flags.use_cmp_features) {
    sancov_state.cmp_feature_set.ForEachNonZeroBit([](size_t idx) {});
    sancov_state.cmp_eq_set.ForEachNonZeroBit([](size_t idx) {});
    sancov_state.cmp_moddiff_set.ForEachNonZeroBit([](size_t idx) {});
    sancov_state.cmp_hamming_set.ForEachNonZeroBit([](size_t idx) {});
    sancov_state.cmp_difflog_set.ForEachNonZeroBit([](size_t idx) {});
  }
  if (sancov_state.flags.path_level != 0)
    sancov_state.path_feature_set.ForEachNonZeroBit([](size_t idx) {});
  if (sancov_state.flags.callstack_level != 0)
    sancov_state.callstack_set.ForEachNonZeroBit([](size_t idx) {});
  sancov_state.sancov_objects.ClearInlineCounters();
}

// Adds a kPCs and/or k8bitCounters feature to `g_features` based on arguments.
// `idx` is a pc_index.
// `counter_value` (non-zero) is a counter value associated with that PC.
static void AddPcIndxedAndCounterToFeatures(size_t idx, uint8_t counter_value) {
  if (sancov_state.flags.use_pc_features) {
    MaybeAddFeature(feature_domains::kPCs.ConvertToMe(idx));
  }
  if (sancov_state.flags.use_counter_features) {
    MaybeAddFeature(feature_domains::k8bitCounters.ConvertToMe(
        Convert8bitCounterToNumber(idx, counter_value)));
  }
}

void PostProcessSancov(int target_return_value) {
  sancov_state.g_features.clear();

  if (target_return_value == -1) return;

  // Convert counters to features.
  sancov_state.pc_counter_set.ForEachNonZeroByte(
      [](size_t idx, uint8_t value) {
        AddPcIndxedAndCounterToFeatures(idx, value);
      },
      0, sancov_state.actual_pc_counter_set_size_aligned);

  // Convert data flow bit set to features.
  if (sancov_state.flags.use_dataflow_features) {
    sancov_state.data_flow_feature_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kDataFlow.ConvertToMe(idx));
    });
  }

  // Convert cmp bit set to features.
  if (sancov_state.flags.use_cmp_features) {
    // TODO(kcc): remove cmp_feature_set.
    sancov_state.cmp_feature_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCMP.ConvertToMe(idx));
    });
    sancov_state.cmp_eq_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCMPEq.ConvertToMe(idx));
    });
    sancov_state.cmp_moddiff_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCMPModDiff.ConvertToMe(idx));
    });
    sancov_state.cmp_hamming_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCMPHamming.ConvertToMe(idx));
    });
    sancov_state.cmp_difflog_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCMPDiffLog.ConvertToMe(idx));
    });
  }

  // Convert path bit set to features.
  if (sancov_state.flags.path_level != 0) {
    sancov_state.path_feature_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kBoundedPath.ConvertToMe(idx));
    });
  }

  // Iterate all threads and get features from TLS data.
  sancov_state.ForEachTls([](ThreadLocalSancovState &tls) {
    if (sancov_state.flags.callstack_level != 0) {
      RunnerCheck(tls.top_frame_sp >= tls.lowest_sp,
                  "bad values of tls.top_frame_sp and tls.lowest_sp");
      size_t sp_diff = tls.top_frame_sp - tls.lowest_sp;
      MaybeAddFeature(feature_domains::kCallStack.ConvertToMe(sp_diff));
    }
  });

  if (sancov_state.flags.callstack_level != 0) {
    sancov_state.callstack_set.ForEachNonZeroBit([](size_t idx) {
      MaybeAddFeature(feature_domains::kCallStack.ConvertToMe(idx));
    });
  }

  // Iterates all non-zero inline 8-bit counters, if they are present.
  // Calls AddPcIndxedAndCounterToFeatures on non-zero counters and zeroes them.
  if (sancov_state.flags.use_pc_features ||
      sancov_state.flags.use_counter_features) {
    sancov_state.sancov_objects.ForEachNonZeroInlineCounter(
        [](size_t idx, uint8_t counter_value) {
          AddPcIndxedAndCounterToFeatures(idx, counter_value);
        });
  }
}

__attribute__((noinline)) void CheckStackLimit(uintptr_t sp) {
  if (sancov_state.flag_helper.centipede_runner_flags) {
    Initializer();
  }
  static std::atomic_flag stack_limit_exceeded = ATOMIC_FLAG_INIT;
  const size_t stack_limit = sancov_state.flags.stack_limit_kb.load() << 10;
  // Check for the stack limit only if sp is inside the stack region.
  if (stack_limit > 0 && tls.stack_region_low &&
      tls.top_frame_sp - sp > stack_limit) {
    if (sancov_state.test_not_running) return;
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

}  // namespace fuzztest::internal

extern "C" void CentipedeSetFailureDescription(const char *description) {
  using fuzztest::internal::sancov_state;
  if (sancov_state.flag_helper.failure_description_path == nullptr) return;
  // Make sure that the write is atomic and only happens once.
  [[maybe_unused]] static int write_once = [=] {
    FILE *f = fopen(sancov_state.flag_helper.failure_description_path, "w");
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
