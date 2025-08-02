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

#ifndef FUZZTEST_CENTIPEDE_FLAG_UTILS_H_
#define FUZZTEST_CENTIPEDE_FLAG_UTILS_H_

#include <stdlib.h>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstring>

#include "absl/base/nullability.h"
#include "./centipede/runner_interface.h"
#include "./centipede/shared_coverage_state.h"

namespace fuzztest::internal {

// Flags derived from CENTIPEDE_RUNNER_FLAGS.
// Flags used in instrumentation callbacks are bit-packed for efficiency.
struct RunTimeFlags {
  RunTimeFlags() {
    path_level = std::min(ThreadLocalRunnerState::kBoundedPathLength,
                          HasIntFlag(":path_level=", 0)),
    use_pc_features = HasFlag(":use_pc_features:");
    use_dataflow_features = HasFlag(":use_dataflow_features:");
    use_cmp_features = HasFlag(":use_cmp_features:");
    callstack_level = HasIntFlag(":callstack_level=", 0);
    use_counter_features = HasFlag(":use_counter_features:");
    use_auto_dictionary = HasFlag(":use_auto_dictionary:");
    timeout_per_input = HasIntFlag(":timeout_per_input=", 0);
    timeout_per_batch = HasIntFlag(":timeout_per_batch=", 0);
    stack_limit_kb = HasIntFlag(":stack_limit_kb=", 0);
    rss_limit_mb = HasIntFlag(":rss_limit_mb=", 0);
    crossover_level = HasIntFlag(":crossover_level=", 50);
    skip_seen_features = HasFlag(":skip_seen_features:");
    ignore_timeout_reports = HasFlag(":ignore_timeout_reports:");
    max_len = HasIntFlag(":max_len=", 4000);
  }

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
};

extern RunTimeFlags run_time_flags;

}  // namespace fuzztest::internal

#endif  // FUZZTEST_CENTIPEDE_FLAG_UTILS_H_
