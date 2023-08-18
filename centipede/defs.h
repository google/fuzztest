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

#ifndef THIRD_PARTY_CENTIPEDE_DEFS_H_
#define THIRD_PARTY_CENTIPEDE_DEFS_H_
// Only simple definitions here. No code, no dependencies.
// span.h is an exception as it's header-only and very simple.

#include <cstddef>
#include <cstdint>
#include <random>
#include <vector>

#include "absl/types/span.h"

namespace centipede {

// Just a good random number generator.
using Rng = std::mt19937_64;

using ByteArray = std::vector<uint8_t>;
using ByteSpan = absl::Span<const uint8_t>;

// Macro used to allow tests to access protected or private members of a class.
#define FRIEND_TEST(test_case_name, test_name) \
  friend class test_case_name##_##test_name##_Test

// We don't want to include <linux/limits.h> or equivalent in any of the .h
// files. So we define kPathMax, and verify that it is >= PATH_MAX in util.cc.
constexpr size_t kPathMax = 4096;

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_DEFS_H_
