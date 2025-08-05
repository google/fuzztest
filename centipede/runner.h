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
#include <time.h>

#include <atomic>

#include "absl/base/const_init.h"
#include "./centipede/byte_array_mutator.h"
#include "./centipede/concurrent_bitset.h"
#include "./centipede/feature.h"
#include "./centipede/knobs.h"
#include "./centipede/runner_interface.h"
#include "./centipede/runner_result.h"
#include "./centipede/shared_coverage_state.h"

namespace fuzztest::internal {

// Like std::lock_guard, but for pthread_mutex_t.
class LockGuard {
 public:
  explicit LockGuard(pthread_mutex_t &mu) : mu_(mu) { pthread_mutex_lock(&mu); }
  ~LockGuard() { pthread_mutex_unlock(&mu_); }

 private:
  pthread_mutex_t &mu_;
};

// One global object of this type is created by the runner at start up.
// All data members will be initialized to zero, unless they have initializers.
// Accesses to the subobjects should be fast, so we are trying to avoid
// extra memory references where possible.
//
// This class has a non-trivial destructor to work with targets that do not use
// the runner or LLVM fuzzer API at all.
//
// TODO(kcc): use a CTOR with absl::kConstInit (will require refactoring).
struct GlobalRunnerState {
  // Used by LLVMFuzzerMutate and initialized in main().
  ByteArrayMutator *byte_array_mutator = nullptr;
  Knobs knobs;

  GlobalRunnerState();
  ~GlobalRunnerState();

  // Runner reads flags from CentipedeGetRunnerFlags(). We don't use flags
  // passed via argv so that argv flags can be passed directly to
  // LLVMFuzzerInitialize, w/o filtering. The flags are separated with
  // ':' on both sides, i.e. like this: ":flag1:flag2:flag3=value3".
  // We do it this way to make the flag parsing code extremely simple. The
  // interface is private between Centipede and the runner and may change.
  //
  // Note that this field reflects the initial runner flags. But some
  // flags can change later (if wrapped with std::atomic).
  const char *centipede_runner_flags = CentipedeGetRunnerFlags();
  const char *arg1 = GetStringFlag(":arg1=");
  const char *arg2 = GetStringFlag(":arg2=");
  const char *arg3 = GetStringFlag(":arg3=");
  // The path to a file where the runner may write the description of failure.
  const char *failure_description_path =
      GetStringFlag(":failure_description_path=");

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

  pthread_mutex_t execution_result_override_mu = PTHREAD_MUTEX_INITIALIZER;
  // If not nullptr, it points to a batch result with either zero or one
  // execution. When an execution result present, it will be passed as the
  // execution result of the current test input. The object is owned and cleaned
  // up by the state, protected by execution_result_override_mu, and set by
  // `CentipedeSetExecutionResult()`.
  BatchResult *execution_result_override;

  // Doubly linked list of TLSs of all live threads.
  ThreadLocalRunnerState *tls_list;
  // Doubly linked list of detached TLSs.
  ThreadLocalRunnerState *detached_tls_list;
  // Guards `tls_list` and `detached_tls_list`.
  pthread_mutex_t tls_list_mu = PTHREAD_MUTEX_INITIALIZER;
  // Iterates all TLS objects under tls_list_mu, except those with `ignore` set.
  // Calls `callback()` on every TLS.
  template <typename Callback>
  void ForEachTls(Callback callback) {
    LockGuard lock(tls_list_mu);
    for (auto *it = tls_list; it; it = it->next) {
      if (!it->ignore) callback(*it);
    }
    for (auto *it = detached_tls_list; it; it = it->next) {
      callback(*it);
    }
  }

  // Reclaims all TLSs in detached_tls_list and cleans up the list.
  void CleanUpDetachedTls();

  // Tracing CMP instructions, capture events from these domains:
  // kCMPEq, kCMPModDiff, kCMPHamming, kCMPModDiffLog, kCMPMsbEq.
  // See https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-data-flow.
  // TODO(kcc): remove cmp_feature_set.
  ConcurrentBitSet<kCmpFeatureSetSize> cmp_feature_set{absl::kConstInit};

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

  // Execution stats for the currently executed input.
  ExecutionResult::Stats stats;

  // CentipedeRunnerMain() sets this to true.
  bool centipede_runner_main_executed = false;

  // Timeout-related machinery.

  // Starts the watchdog thread that terminates the runner if any of the
  // rss/time limits are exceeded.
  void StartWatchdogThread();
  // Resets the per-input timer. Call this before executing every input.
  void ResetTimers();

  // Per-batch timer. Initially, zero. ResetInputTimer() sets it to the current
  // time before the first input and never resets it.
  std::atomic<time_t> batch_start_time;

  // The Watchdog thread sets this to true.
  std::atomic<bool> watchdog_thread_started;
};

extern GlobalRunnerState state;

}  // namespace fuzztest::internal

#endif  // THIRD_PARTY_CENTIPEDE_RUNNER_H_
