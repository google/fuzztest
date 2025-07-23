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

namespace fuzztest::internal {

// Flags derived from CENTIPEDE_RUNNER_FLAGS.
// Flags used in instrumentation callbacks are bit-packed for efficiency.
struct FlagHelper {
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

  // To default to true when `centipede_runner_flags` is not set.
  bool HasFeatureFlag(const char *absl_nonnull flag) const {
    if (!centipede_runner_flags) return true;
    return strstr(centipede_runner_flags, flag) != nullptr;
  }

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

extern FlagHelper flag_helper;

}  // namespace fuzztest::internal

#endif  // FUZZTEST_CENTIPEDE_FLAG_UTILS_H_
