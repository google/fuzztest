// Copyright 2025 Google LLC
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

#ifndef FUZZTEST_RUST_CPP_COMMON_RUNTIME_SYMBOL_NAME_UTILS_H_
#define FUZZTEST_RUST_CPP_COMMON_RUNTIME_SYMBOL_NAME_UTILS_H_

#include <cctype>

#include "absl/strings/string_view.h"

namespace fuzztest::internal {

inline void ConsumeFileAndLineNumber(absl::string_view& v) {
  // We're essentially matching the regexp "[^:]\:\d+ ", but manually since we
  // don't want to introduce a dependency on RE2.
  absl::string_view::size_type pos = 0;
  while (pos < v.size()) {
    pos = v.find(':', pos);
    if (pos == v.npos) return;
    // Skip the colon.
    ++pos;
    if (pos >= v.size() || !std::isdigit(v[pos])) {
      // Colon not followed by a digit. Skip any subsequent colons and continue.
      while (pos < v.size() && v[pos] == ':') ++pos;
      continue;
    }
    // Skip the digits.
    ++pos;
    while (pos < v.size() && std::isdigit(v[pos])) ++pos;
    if (pos >= v.size() || v[pos] != ' ') continue;
    // Skip the space.
    ++pos;
    v.remove_prefix(pos);
    return;
  }
}

}  // namespace fuzztest::internal

#endif  // FUZZTEST_RUST_CPP_COMMON_RUNTIME_SYMBOL_NAME_UTILS_H_
