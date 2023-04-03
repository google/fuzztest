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

#include <cstddef>
#include <cstdint>

// Example demonstrating how we can pass "user defined" features to Centipede.
// The user code needs to define an array of uint64_t in the special section
// "__centipede_extra_features". Several such arrays can be defined.
// Use __attribute__((used, retain)), otherwise the array may be removed by
// compiler. Then, the user code sets any of the elements of this array to any
// values. The order of values doesn't matter. The presence of duplicates
// doesn't matter, but avoid them so that not to overflow the array. Value `0`
// will be ignored. Those values would be consumed by Centipede as "features",
// see feature.h. Several of the high order bits of these values will be ignored
// so that the features can be added to the kUserDefined domain.
// TODO(kcc): graduate this from an experiment and document properly.
static constexpr size_t kNumExtraFeatures = 10000;  // Any number.
__attribute__((used, retain, section("__centipede_extra_features")))
static uint64_t extra_features[kNumExtraFeatures];

// Populates extra_features[] with lots of different user defined features.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size > kNumExtraFeatures) return -1;  // input too large, ignore.
  for (size_t i = 0; i < size; ++i) extra_features[i] = (i << 8) | data[i];
  return 0;
}
