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
#include "absl/base/nullability.h"
#include "absl/numeric/bits.h"
#include "./centipede/byte_array_mutator.h"
#include "./centipede/callstack.h"
#include "./centipede/concurrent_bitset.h"
#include "./centipede/concurrent_byteset.h"
#include "./centipede/feature.h"
#include "./centipede/hashed_ring_buffer.h"
#include "./centipede/knobs.h"
#include "./centipede/reverse_pc_table.h"
#include "./centipede/runner_cmp_trace.h"
#include "./centipede/runner_dl_info.h"
#include "./centipede/runner_interface.h"
#include "./centipede/runner_result.h"
#include "./centipede/runner_sancov_object.h"

namespace fuzztest::internal {

// Flags derived from CENTIPEDE_RUNNER_FLAGS.
// Flags used in instrumentation callbacks are bit-packed for efficiency.
struct RunTimeFlags {
  std::atomic<uint64_t> timeout_per_input;
  uint64_t timeout_per_batch;
  std::atomic<uint64_t> rss_limit_mb;
  uint64_t crossover_level;
  uint64_t ignore_timeout_reports : 1;
  uint64_t max_len;
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

  // Flags.
  RunTimeFlags run_time_flags = {
      /*timeout_per_input=*/HasIntFlag(":timeout_per_input=", 0),
      /*timeout_per_batch=*/HasIntFlag(":timeout_per_batch=", 0),
      /*rss_limit_mb=*/HasIntFlag(":rss_limit_mb=", 0),
      /*crossover_level=*/HasIntFlag(":crossover_level=", 50),
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

  // Per-input timer. Initially, zero. ResetInputTimer() sets it to the current
  // time.
  std::atomic<time_t> input_start_time;
  // Per-batch timer. Initially, zero. ResetInputTimer() sets it to the current
  // time before the first input and never resets it.
  std::atomic<time_t> batch_start_time;

  // The Watchdog thread sets this to true.
  std::atomic<bool> watchdog_thread_started;
};

// extern GlobalRunnerState state;

}  // namespace fuzztest::internal

#endif  // THIRD_PARTY_CENTIPEDE_RUNNER_H_
