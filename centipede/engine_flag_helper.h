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

#ifndef FUZZTEST_CENTIPEDE_ENGINE_FLAG_HELPER_H_
#define FUZZTEST_CENTIPEDE_ENGINE_FLAG_HELPER_H_

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "absl/base/nullability.h"

namespace fuzztest::internal {

// Processes the `flags` buffer in-place, which comes with the format of
// :(NAME=VALUE:|NAME:)+, where NAME and VALUE can contain escaped chars with
// backslash (\). It drops any chars before the first colon or after the last
// unescaped colon, drops any empty flags, and replaces unescaped colons with
// '\0'. Returns the number of chars in the processed result.
//
// Returns 0 if no proper flags are found in the `flags` buffer.
size_t ProcessEngineFlags(char* flags, size_t size);

// Helper class for processing and reading the engine flags.
class EngineFlagHelper {
 public:
  // Constructs the helper for a C-string `flags` with the format of :(ENTRY:)+.
  explicit EngineFlagHelper(const char* absl_nullable flags);

  EngineFlagHelper(const EngineFlagHelper&) = delete;
  EngineFlagHelper& operator=(const EngineFlagHelper&) = delete;

  ~EngineFlagHelper();

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

#endif  // FUZZTEST_CENTIPEDE_ENGINE_FLAG_HELPER_H_
