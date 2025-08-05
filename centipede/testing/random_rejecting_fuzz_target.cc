// Copyright 2025 The Centipede Authors.
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

#include <cstddef>
#include <cstdint>

static constexpr size_t kNumExtraFeatures = 10000;  // Any number.
__attribute__((used, retain,
               section("__centipede_extra_features"))) static uint64_t
    extra_features[kNumExtraFeatures];

static uint64_t run_number = 0;

// "Randomly" fails half the time, but puts a user feature into the array when
// it does.  This allows us to verify that inputs that return -1 are properly
// cleaned up and do not leak user features into future inputs that return 0.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  ++run_number;
  if (run_number % 2 == 0) {
    uint64_t domain = 1;
    extra_features[0] = (domain << 32) | (1 << 8) | 1;
    return -1;
  }
  return 0;
}
