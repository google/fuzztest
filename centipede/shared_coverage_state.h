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

#ifndef FUZZTEST_CENTIPEDE_SHARED_COVERAGE_STATE_H_
#define FUZZTEST_CENTIPEDE_SHARED_COVERAGE_STATE_H_

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>

#include "absl/base/const_init.h"
#include "absl/base/nullability.h"
#include "absl/numeric/bits.h"
#include "./centipede/callstack.h"
#include "./centipede/concurrent_bitset.h"
#include "./centipede/concurrent_byteset.h"
#include "./centipede/feature.h"
#include "./centipede/hashed_ring_buffer.h"
#include "./centipede/reverse_pc_table.h"
#include "./centipede/runner_cmp_trace.h"
#include "./centipede/runner_dl_info.h"
#include "./centipede/runner_interface.h"
#include "./centipede/runner_sancov_object.h"

namespace fuzztest::internal {

// An arbitrarily large size.
static constexpr size_t kCmpFeatureSetSize = 1 << 18;

// Flags derived from CENTIPEDE_RUNNER_FLAGS.
// Flags used in instrumentation callbacks are bit-packed for efficiency.
struct RunTimeFlags {
  uint64_t path_level : 8;
  uint64_t use_pc_features : 1;
  uint64_t use_dataflow_features : 1;
  uint64_t use_cmp_features : 1;
  uint64_t callstack_level : 8;
  uint64_t use_counter_features : 1;
  uint64_t use_auto_dictionary : 1;
  std::atomic<uint64_t> timeout_per_input;
  uint64_t timeout_per_batch;
  std::atomic<uint64_t> stack_limit_kb;
  std::atomic<uint64_t> rss_limit_mb;
  uint64_t crossover_level;
  uint64_t skip_seen_features : 1;
  uint64_t ignore_timeout_reports : 1;
  uint64_t max_len;
};

// One such object is created in runner's TLS.
// There is no CTOR, since we don't want to use the brittle and lazy TLS CTORs.
// All data members are zero-initialized during thread creation.
struct ThreadLocalRunnerState {
  // Traces the memory comparison of `n` bytes at `s1` and `s2` called at
  // `caller_pc` with `is_equal` indicating whether the two memory regions have
  // equal contents. May add cmp features and auto-dictionary entries if
  // enabled.
  void TraceMemCmp(uintptr_t caller_pc, const uint8_t *s1, const uint8_t *s2,
                   size_t n,
                   bool is_equal);  // Not called on shared coverage library

  // Intrusive doubly-linked list of TLS objects.
  // Guarded by state.tls_list_mu.
  ThreadLocalRunnerState *next, *prev;

  // The pthread_create() interceptor calls OnThreadStart() before the thread
  // callback. The main thread also calls OnThreadStart(). OnThreadStop() will
  // be called when thread termination is detected internally - see runner.cc.
  void OnThreadStart();  // Not called on shared coverage library
  void OnThreadStop();   // Not called on shared coverage library

  // Whether OnThreadStart() is called on this thread. This is used as a proxy
  // of the readiness of the lower-level runtime.
  bool started;

  // Paths are thread-local, so we maintain the current bounded path here.
  // We allow paths of up to 100, controlled at run-time via the "path_level".
  static constexpr uint64_t kBoundedPathLength = 100;
  HashedRingBuffer<kBoundedPathLength> path_ring_buffer;

  // Value of SP in the top call frame of the thread, computed in OnThreadStart.
  uintptr_t top_frame_sp;
  // The lower bound of the stack region of this thread. 0 means unknown.
  uintptr_t stack_region_low;
  // Lowest observed value of SP.
  uintptr_t lowest_sp;

  // The (imprecise) call stack is updated by the PC callback.
  CallStack<> call_stack;

  // Cmp traces capture the arguments of CMP instructions, memcmp, etc.
  // We have dedicated traces for 2-, 4-, and 8-byte comparison, and
  // a catch-all `cmp_traceN` trace for memcmp, etc.
  CmpTrace<2, 64> cmp_trace2;
  CmpTrace<4, 64> cmp_trace4;
  CmpTrace<8, 64> cmp_trace8;
  CmpTrace<0, 64> cmp_traceN;

  // Set this to true if the thread needs to be ignored in ForEachTLS.
  // It should be always false if the state is in the global detached_tls_list.
  bool ignore;
};

struct CoverageFlags {
  uint64_t use_cmp_features : 1;
};

struct SharedCoverageState {
  const char *centipede_runner_flags = CentipedeGetRunnerFlags();

  // Flags.
  RunTimeFlags run_time_flags = {
      /*path_level=*/std::min(ThreadLocalRunnerState::kBoundedPathLength,
                              HasIntFlag(":path_level=", 0)),
      /*use_pc_features=*/HasFlag(":use_pc_features:"),
      /*use_dataflow_features=*/HasFlag(":use_dataflow_features:"),
      /*use_cmp_features=*/HasFlag(":use_cmp_features:"),
      /*callstack_level=*/HasIntFlag(":callstack_level=", 0),
      /*use_counter_features=*/HasFlag(":use_counter_features:"),
      /*use_auto_dictionary=*/HasFlag(":use_auto_dictionary:"),
      /*timeout_per_input=*/HasIntFlag(":timeout_per_input=", 0),
      /*timeout_per_batch=*/HasIntFlag(":timeout_per_batch=", 0),
      /*stack_limit_kb=*/HasIntFlag(":stack_limit_kb=", 0),
      /*rss_limit_mb=*/HasIntFlag(":rss_limit_mb=", 0),
      /*crossover_level=*/HasIntFlag(":crossover_level=", 50),
      /*skip_seen_features=*/HasFlag(":skip_seen_features:"),
      /*ignore_timeout_reports=*/HasFlag(":ignore_timeout_reports:"),
      /*max_len=*/HasIntFlag(":max_len=", 4000),
  };

  // Returns true iff `flag` is present.
  // Typical usage: pass ":some_flag:", i.e. the flag name surrounded with ':'.
  // TODO(ussuri): Refactor `char *` into a `string_view`.
  bool HasFlag(const char *absl_nonnull flag) const {
    if (!centipede_runner_flags) return false;
    return strstr(centipede_runner_flags, flag) != nullptr;
  }

  // If a flag=value pair is present, returns value,
  // otherwise returns `default_value`.
  // Typical usage: pass ":some_flag=".
  // TODO(ussuri): Refactor `char *` into a `string_view`.
  uint64_t HasIntFlag(const char *absl_nonnull flag,
                      uint64_t default_value) const {
    if (!centipede_runner_flags) return default_value;
    const char *beg = strstr(centipede_runner_flags, flag);
    if (!beg) return default_value;
    return atoll(beg + strlen(flag));  // NOLINT: can't use strto64, etc.
  }

  // If a :flag=value: pair is present returns value, otherwise returns nullptr.
  // The result is obtained by calling strndup, so make sure to save
  // it in `this` to avoid a leak.
  // Typical usage: pass ":some_flag=".
  // TODO(ussuri): Refactor `char *` into a `string_view`.
  const char *absl_nullable GetStringFlag(const char *absl_nonnull flag) const {
    if (!centipede_runner_flags) return nullptr;
    // Extract "value" from ":flag=value:" inside centipede_runner_flags.
    const char *beg = strstr(centipede_runner_flags, flag);
    if (!beg) return nullptr;
    const char *value_beg = beg + strlen(flag);
    const char *end = strstr(value_beg, ":");
    if (!end) return nullptr;
    return strndup(value_beg, end - value_beg);
  }

  // Computed by DlInfo().
  // Usually, the main object is the executable binary containing main()
  // and most of the executable code (we assume that the target is
  // built in mostly-static mode, i.e. -dynamic_mode=off).
  // When the `dl_path_suffix` runner flag is provided, the main_object refers
  // to the dynamic library (DSO) pointed to by this flag.
  //
  // Note: this runner currently does not support more than one instrumented
  // DSO in the process, i.e. you either instrument the main binary, or one DSO.
  // Supporting more than one DSO will require major changes,
  // major added complexity, and potentially cause slowdown.
  // There is currently no motivation for such a change.
  DlInfo main_object;

  // State for SanitizerCoverage.
  // See https://clang.llvm.org/docs/SanitizerCoverage.html.
  SanCovObjectArray sancov_objects;
  // An arbitrarily large size.
  static constexpr size_t kDataFlowFeatureSetSize = 1 << 18;
  ConcurrentBitSet<kDataFlowFeatureSetSize> data_flow_feature_set{
      absl::kConstInit};

  // Tracing CMP instructions, capture events from these domains:
  // kCMPEq, kCMPModDiff, kCMPHamming, kCMPModDiffLog, kCMPMsbEq.
  // See https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-data-flow.
  ConcurrentBitSet<kCmpFeatureSetSize> cmp_eq_set{absl::kConstInit};
  ConcurrentBitSet<kCmpFeatureSetSize> cmp_moddiff_set{absl::kConstInit};
  ConcurrentBitSet<kCmpFeatureSetSize> cmp_hamming_set{absl::kConstInit};
  ConcurrentBitSet<kCmpFeatureSetSize> cmp_difflog_set{absl::kConstInit};

  // We think that call stack produces rich signal, so we give a few bits to it.
  static constexpr size_t kCallStackFeatureSetSize = 1 << 24;
  ConcurrentBitSet<kCallStackFeatureSetSize> callstack_set{absl::kConstInit};

  // kMaxNumPcs is the maximum number of instrumented PCs in the binary.
  // We can be generous here since the unused memory will not cost anything.
  // `pc_counter_set` is a static byte set supporting up to kMaxNumPcs PCs.
  static constexpr size_t kMaxNumPcs = 1 << 28;
  TwoLayerConcurrentByteSet<kMaxNumPcs> pc_counter_set{absl::kConstInit};
  // This is the actual number of PCs, aligned up to
  // pc_counter_set::kSizeMultiple, computed at startup.
  size_t actual_pc_counter_set_size_aligned;

  // Used by trace_pc instrumentation. Populated if `pcs_file_path` flag is set.
  ReversePCTable reverse_pc_table;

  // An arbitrarily large size.
  static constexpr size_t kPathBitSetSize = 1 << 25;
  // Observed paths. The total number of observed paths for --path_level=N
  // can be up to NumPCs**N.
  // So, we make the bitset very large, but it may still saturate.
  ConcurrentBitSet<kPathBitSetSize> path_feature_set{absl::kConstInit};

  // Per-input timer. Initially, zero. ResetInputTimer() sets it to the current
  // time.
  std::atomic<time_t> input_start_time;

  // An arbitrarily large size.
  static const size_t kMaxFeatures = 1 << 20;
  // FeatureArray used to accumulate features from all sources.
  FeatureArray<kMaxFeatures> g_features;

  // Features that were seen before.
  static constexpr size_t kSeenFeatureSetSize =
      absl::bit_ceil(feature_domains::kLastDomain.end());
  ConcurrentBitSet<kSeenFeatureSetSize> seen_features{absl::kConstInit};
};

__attribute__((noinline))  // so that we see it in profile.
extern "C" void PrepareSharedCoverage(bool full_clear);

__attribute__((noinline))  // so that we see it in profile.
extern "C" void PostProcessSharedCoverage();

void MaybeAddFeature(feature_t feature);

// Check for stack limit for the stack pointer `sp` in the current thread.
void CheckStackLimit(uintptr_t sp);

extern SharedCoverageState shared_coverage_state;
// extern RunTimeFlags run_time_flags;
extern __thread ThreadLocalRunnerState tls;

}  // namespace fuzztest::internal

#endif  // FUZZTEST_CENTIPEDE_SHARED_COVERAGE_STATE_H_
