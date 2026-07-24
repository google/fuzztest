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

#ifndef FUZZTEST_CENTIPEDE_DISPATCHER_FLAG_HELPER_H_
#define FUZZTEST_CENTIPEDE_DISPATCHER_FLAG_HELPER_H_

#include <stdlib.h>

#include <cstdint>
#include <cstring>

#if defined(_WIN32)
inline static char* strndup(const char* s, size_t n) {
  size_t len = strnlen(s, n);
  char* ret = static_cast<char*>(malloc(len + 1));
  if (ret) {
    memcpy(ret, s, len);
    ret[len] = '\0';
  }
  return ret;
}
#endif

#include "absl/base/nullability.h"

namespace fuzztest::internal {

struct DispatcherFlagHelper {
  // We don't use flags passed via argv so that argv flags can be passed
  // directly to LLVMFuzzerInitialize, w/o filtering. The flags are separated
  // with ':' on both sides, i.e. like this: ":flag1:flag2:flag3=value3".
  // We do it this way to make the flag parsing code extremely simple. The
  // interface is private between Centipede and the runner and may change.
  DispatcherFlagHelper(const char *absl_nullable flags_) : flags(flags_) {}

  const char *absl_nullable flags;

  // Returns true iff `flag` is present.
  // Typical usage: pass ":some_flag:", i.e. the flag name surrounded with ':'.
  // TODO(ussuri): Refactor `char *` into a `string_view`.
  bool HasFlag(const char *absl_nonnull flag) const {
    if (!flags) return false;
    return strstr(flags, flag) != nullptr;
  }

  // If a flag=value pair is present, returns value,
  // otherwise returns `default_value`.
  // Typical usage: pass ":some_flag=".
  // TODO(ussuri): Refactor `char *` into a `string_view`.
  uint64_t HasIntFlag(const char *absl_nonnull flag,
                      uint64_t default_value) const {
    if (!flags) return default_value;
    const char *beg = strstr(flags, flag);
    if (!beg) return default_value;
    return atoll(beg + strlen(flag));  // NOLINT: can't use strto64, etc.
  }

  // If a :flag=value: pair is present returns value, otherwise returns nullptr.
  // The result is obtained by calling strndup, so make sure to save
  // it in `this` to avoid a leak.
  // Typical usage: pass ":some_flag=".
  // TODO(ussuri): Refactor `char *` into a `string_view`.
  const char *absl_nullable GetStringFlag(const char *absl_nonnull flag) const {
    if (!flags) return nullptr;
    // Extract "value" from ":flag=value:" inside centipede_runner_flags.
    const size_t flag_len = strlen(flag);
    const char* beg = flags;
    while (true) {
      beg = strstr(beg, flag);
      if (beg == nullptr) return nullptr;
      // Find the closest non-backslash before the candiate position.
      const char* cur = beg - 1;
      while (cur >= flags && *cur == '\\') --cur;
      // There are even number of backslashes before the flag, meaning it's not
      // escaped.
      if (((beg - cur) & 1) == 1) break;
      beg = beg + flag_len;
    }
    if (!beg) return nullptr;
    const char* value_beg = beg + flag_len;
    const char* end = value_beg;
    while (*end) {
      if (*end == '\\' && *(end + 1) != 0) {
        end += 2;
        continue;
      }
      if (*end == ':') break;
      ++end;
    }
    if (!end || !*end) return nullptr;
    char* r = strndup(value_beg, end - value_beg);
    size_t d = 0;
    for (const char* c = r; *c != 0; ++c) {
      if (*c == '\\' && *(c + 1) != 0) ++c;
      r[d++] = *c;
    }
    r[d] = 0;
    return r;
  }
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_CENTIPEDE_DISPATCHER_FLAG_HELPER_H_
