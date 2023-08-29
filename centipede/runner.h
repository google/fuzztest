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

#ifndef THIRD_PARTY_CENTIPEDE_RUNNER_H_
#define THIRD_PARTY_CENTIPEDE_RUNNER_H_

#include <pthread.h>  // NOLINT: use pthread to avoid extra dependencies.
#include <string.h>
#include <time.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdlib>

#include "absl/base/const_init.h"
#include "./centipede/byte_array_mutator.h"
#include "./centipede/callstack.h"
#include "./centipede/concurrent_bitset.h"
#include "./centipede/concurrent_byteset.h"
#include "./centipede/feature.h"
#include "./centipede/hashed_ring_buffer.h"
#include "./centipede/knobs.h"
#include "./centipede/pc_info.h"
#include "./centipede/reverse_pc_table.h"
#include "./centipede/runner_cmp_trace.h"
#include "./centipede/runner_dl_info.h"
#include "./centipede/runner_result.h"
#include "./centipede/runner_sancov_object.h"

namespace centipede {

// Like std::lock_guard, but for pthread_mutex_t.
class LockGuard {
 public:
  explicit LockGuard(pthread_mutex_t &mu) : mu_(mu) { pthread_mutex_lock(&mu); }
  ~LockGuard() { pthread_mutex_unlock(&mu_); }

 private:
  pthread_mutex_t &mu_;
};

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
  uint64_t timeout_per_input;
  uint64_t timeout_per_batch;
  uint64_t rss_limit_mb;
  uint64_t crossover_level;
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
                   size_t n, bool is_equal);

  // Intrusive doubly-linked list of TLS objects.
  // Guarded by state.tls_list_mu.
  ThreadLocalRunnerState *next, *prev;

  // The pthread_create() interceptor calls OnThreadStart()/OnThreadStop()
  // before/after the thread callback.
  // The main thread calls OnThreadStart().
  void OnThreadStart();
  void OnThreadStop();

  // Paths are thread-local, so we maintain the current bounded path here.
  // We allow paths of up to 100, controlled at run-time via the "path_level".
  static constexpr size_t kBoundedPathLength = 100;
  HashedRingBuffer<kBoundedPathLength> path_ring_buffer;

  // Value of SP in the top call frame of the thread, computed in OnThreadStart.
  uintptr_t top_frame_sp;
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
  bool ignore;
};

// One global object of this type is created by the runner at start up.
// All data members will be initialized to zero, unless they have initializers.
// Accesses to the subobjects should be fast, so we are trying to avoid
// extra memory references where possible.
// TODO(kcc): use a CTOR with absl::kConstInit (will require refactoring).
struct GlobalRunnerState {
  // Used by LLVMFuzzerMutate and initialized in main().
  ByteArrayMutator *byte_array_mutator = nullptr;
  Knobs knobs;

  GlobalRunnerState();
  ~GlobalRunnerState();

  // Runner reads flags from a dedicated env var, CENTIPEDE_RUNNER_FLAGS.
  // We don't use flags passed via argv so that argv flags can be passed
  // directly to LLVMFuzzerInitialize, w/o filtering. The flags passed in
  // CENTIPEDE_RUNNER_FLAGS are separated with ':' on both sides, i.e. like
  // this: CENTIPEDE_RUNNER_FLAGS=":flag1:flag2:". We do it this way to make the
  // flag parsing code extremely simple. The interface is private between
  // Centipede and the runner and may change.
  const char *centipede_runner_flags = getenv("CENTIPEDE_RUNNER_FLAGS");
  const char *arg1 = GetStringFlag(":arg1=");
  const char *arg2 = GetStringFlag(":arg2=");
  const char *arg3 = GetStringFlag(":arg3=");
  // The path to a file where the runner may write the description of failure.
  const char *failure_description_path =
      GetStringFlag(":failure_description_path=");

  // Flags.
  RunTimeFlags run_time_flags = {
      .path_level = std::min(ThreadLocalRunnerState::kBoundedPathLength,
                             HasIntFlag(":path_level=", 0)),
      .use_pc_features = HasFlag(":use_pc_features:"),
      .use_dataflow_features = HasFlag(":use_dataflow_features:"),
      .use_cmp_features = HasFlag(":use_cmp_features:"),
      .callstack_level = HasIntFlag(":callstack_level=", 0),
      .use_counter_features = HasFlag(":use_counter_features:"),
      .use_auto_dictionary = HasFlag(":use_auto_dictionary:"),
      .timeout_per_input = HasIntFlag(":timeout_per_input=", 0),
      .timeout_per_batch = HasIntFlag(":timeout_per_batch=", 0),
      .rss_limit_mb = HasIntFlag(":rss_limit_mb=", 0),
      .crossover_level = HasIntFlag(":crossover_level=", 50)};

  // Returns true iff `flag` is present.
  // Typical usage: pass ":some_flag:", i.e. the flag name surrounded with ':'.
  bool HasFlag(const char *flag) const {
    if (!centipede_runner_flags) return false;
    return strstr(centipede_runner_flags, flag) != nullptr;
  }

  // If a flag=value pair is present, returns value,
  // otherwise returns `default_value`.
  // Typical usage: pass ":some_flag=".
  uint64_t HasIntFlag(const char *flag, uint64_t default_value) const {
    if (!centipede_runner_flags) return default_value;
    const char *beg = strstr(centipede_runner_flags, flag);
    if (!beg) return default_value;
    return atoll(beg + strlen(flag));  // NOLINT: can't use strto64, etc.
  }

  // If a :flag=value: pair is present returns value, otherwise returns nullptr.
  // The result is obtained by calling strndup, so make sure to save
  // it in `this` to avoid a leak.
  // Typical usage: pass ":some_flag=".
  const char *GetStringFlag(const char *flag) const {
    if (!centipede_runner_flags) return nullptr;
    // Extract "value" from ":flag=value:" inside centipede_runner_flags.
    const char *beg = strstr(centipede_runner_flags, flag);
    if (!beg) return nullptr;
    const char *value_beg = beg + strlen(flag);
    const char *end = strstr(value_beg, ":");
    if (!end) return nullptr;
    return strndup(value_beg, end - value_beg);
  }

  // Doubly linked list of TLSs of all live threads.
  ThreadLocalRunnerState *tls_list;
  pthread_mutex_t tls_list_mu;  // Guards tls_list.
  // Iterates all TLS objects under tls_list_mu, except those with `ignore` set.
  // Calls `callback()` on every TLS.
  template <typename Callback>
  void ForEachTls(Callback callback) {
    LockGuard lock(tls_list_mu);
    for (auto *it = tls_list; it; it = it->next) {
      if (!it->ignore) callback(*it);
    }
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
  static const size_t kBitSetSize = 1 << 18;  // Arbitrary large size.
  ConcurrentBitSet<kBitSetSize> data_flow_feature_set{absl::kConstInit};

  // Tracing CMP instructions, capture events from these domains:
  // kCMPEq, kCMPModDiff, kCMPHamming, kCMPModDiffLog, kCMPMsbEq.
  // See https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-data-flow.
  static const size_t kCmpFeatureSetSize = 1 << 18;  // Arbitrary large size.
  // TODO(kcc): remove cmp_feature_set.
  ConcurrentBitSet<kCmpFeatureSetSize> cmp_feature_set{absl::kConstInit};
  ConcurrentBitSet<kCmpFeatureSetSize> cmp_eq_set{absl::kConstInit};
  ConcurrentBitSet<kCmpFeatureSetSize> cmp_moddiff_set{absl::kConstInit};
  ConcurrentBitSet<kCmpFeatureSetSize> cmp_hamming_set{absl::kConstInit};
  ConcurrentBitSet<kCmpFeatureSetSize> cmp_difflog_set{absl::kConstInit};

  // We think that call stack produces rich signal, so we give a few bits to it.
  static const size_t kCallStackFeatureSetSize = 1 << 24;
  ConcurrentBitSet<kCallStackFeatureSetSize> callstack_set{absl::kConstInit};

  // kMaxNumPcs is the maximum number of instrumented PCs in the binary.
  // We can be generous here since the unused memory will not cost anything.
  // `pc_counter_set` is a static byte set supporting up to kMaxNumPcs PCs.
  static constexpr size_t kMaxNumPcs = 1 << 28;
  TwoLayerConcurrentByteSet<kMaxNumPcs> pc_counter_set{absl::kConstInit};
  // This is the actual number of PCs, aligned up to
  // pc_counter_set::kSizeMultiple, computed at startup.
  size_t actual_pc_counter_set_size_aligned;

  // Initialized in CTOR from the __centipede_extra_features section.
  feature_t *user_defined_begin;
  feature_t *user_defined_end;

  // We use edge instrumentation w/ callbacks to implement bounded-path
  // coverage.
  // * The current PC is converted to an offset (a PC index).
  // * The offset is pushed to a HashedRingBuffer, producing a hash.
  // * The resulting hash represents N most recent PCs, we use it as a feature.
  //
  // WARNING: this is highly experimental.
  // This is far from perfect and may be not sensitive enough in some cases
  // and create exponential number of features in other cases.
  // Some areas to experiment with:
  // * Handle only function-entry PCs, i.e. use call paths, not branch paths.
  // * Play with the length of the path (kBoundedPathLength)
  // * Use call stacks instead of paths (via unwinding or other
  // instrumentation).

  static const size_t kPathBitSetSize = 1 << 25;  // Arbitrary very large size.
  // Observed paths. The total number of observed paths for --path_level=N
  // can be up to NumPCs**N.
  // So, we make the bitset very large, but it may still saturate.
  ConcurrentBitSet<kPathBitSetSize> path_feature_set{absl::kConstInit};

  // Execution stats for the currently executed input.
  ExecutionResult::Stats stats;

  // Used by trace_pc instrumentation. Populated if `pcs_file_path` flag is set.
  ReversePCTable reverse_pc_table;

  // CentipedeRunnerMain() sets this to true.
  bool centipede_runner_main_executed = false;

  // Timeout-related machinery.

  // If the timeout_per_input and/or rss_limit_mb flags are passed, initializes
  // the watchdog thread that terminates the runner if either of those limits
  // are exceeded.
  void StartWatchdogThread();
  // Resets the per-input timer. Call this before executing every input.
  void ResetTimers();

  // Per-input timer. Initially, zero. ResetInputTimer() sets it to the current
  // time.
  std::atomic<time_t> input_start_time;
  // Per-batch timer. Initially, zero. ResetInputTimer() sets it to the current
  // time before the first input and never resets it.
  std::atomic<time_t> batch_start_time;

  // The Watchdog thread sets this to true.
  std::atomic<bool> watchdog_thread_started;

  // An arbitrary large size.
  static const size_t kMaxFeatures = 1 << 20;
  // FeatureArray used to accumulate features from all sources.
  FeatureArray<kMaxFeatures> g_features;
};

extern GlobalRunnerState state;
extern __thread ThreadLocalRunnerState tls;

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_RUNNER_H_
