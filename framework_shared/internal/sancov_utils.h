// Copyright 2026 Google LLC
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

#ifndef FUZZTEST_FRAMEWORK_SHARED_INTERNAL_SANCOV_UTILS_H_
#define FUZZTEST_FRAMEWORK_SHARED_INTERNAL_SANCOV_UTILS_H_

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string_view>

#include "absl/base/attributes.h"
#include "absl/base/nullability.h"
#include "absl/base/optimization.h"

namespace fuzztest::internal {

[[noreturn]] ABSL_ATTRIBUTE_NOINLINE inline void SancovCheckFail(
    const char* absl_nonnull file, int line, const char* absl_nonnull expr,
    const char* absl_nonnull error) {
  fprintf(stderr, "%s:%d: SANCOV_CHECK(%s) failed: %s\n", file, line, expr,
          error);
  exit(1);
}

// A rough equivalent of "FUZZTEST_CHECK(condition) << error;".
#define SANCOV_CHECK(condition, error)                                      \
  do {                                                                      \
    if (ABSL_PREDICT_FALSE(!(condition))) {                                 \
      ::fuzztest::internal::SancovCheckFail(__FILE__, __LINE__, #condition, \
                                            (error));                       \
    }                                                                       \
  } while (0)

// Helper class for processing and reading the sancov runtime flags.
//
// TODO(b/587967420): Remove `SancovFlagHelper` once `sancov_runtime.h` takes
// explicit C config options instead of parsing `CENTIPEDE_RUNNER_FLAGS`.
class SancovFlagHelper {
 public:
  // Constructs the helper for a C-string `flags` with the format of :(ENTRY:)+.
  explicit SancovFlagHelper(const char* absl_nullable flags);

  SancovFlagHelper(const SancovFlagHelper&) = delete;
  SancovFlagHelper& operator=(const SancovFlagHelper&) = delete;

  ~SancovFlagHelper();

  bool HasSwitchFlag(std::string_view flag) const;

  uint64_t GetIntFlag(std::string_view header, uint64_t default_value) const;

  const char* absl_nullable GetStringFlag(std::string_view header) const;

 private:
  // Returns an entry in the flags for `flag`. If `match_whole` is set, match
  // `flag` as the whole entry, otherwise match it as a prefix.
  const char* absl_nullable FindEntry(std::string_view flag,
                                      bool match_whole = false) const;

  char* absl_nullable flags_;
  size_t size_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FRAMEWORK_SHARED_INTERNAL_SANCOV_UTILS_H_
