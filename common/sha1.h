// Copyright 2024 The Centipede Authors.
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

#ifndef FUZZTEST_COMMON_SHA1_H_
#define FUZZTEST_COMMON_SHA1_H_

#include <cstddef>
#include <cstdint>

#include "absl/base/nullability.h"

namespace centipede {

inline constexpr size_t kShaDigestLength = 20;

// Computes the SHA1 hash of the data given by `data` and `len`, and writes the
// result to `out`. `out` must have at least `kShaDigestLength` bytes of space.
void SHA1(absl::Nonnull<const uint8_t *> data, size_t len,
          absl::Nonnull<uint8_t *> out);

}  // namespace centipede

#endif  // FUZZTEST_COMMON_SHA1_H_
