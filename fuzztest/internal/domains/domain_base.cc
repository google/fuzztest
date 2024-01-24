// Copyright 2024 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./fuzztest/internal/domains/domain_base.h"

#include <iostream>
#include <random>

#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "./fuzztest/internal/seed_seq.h"

namespace fuzztest::internal {

void DestabilizeBitGen(absl::BitGenRef bitgen) {
  static constexpr int kMaxSkippedValues = 2;
  static int num_skipped_values = [] {
    std::seed_seq seed_sequence = GetFromEnvOrMakeSeedSeq(std::cerr);
    std::mt19937 auxiliary_prng{seed_sequence};
    return absl::Uniform(auxiliary_prng, 0, kMaxSkippedValues + 1);
  }();
  for (int i = 0; i < num_skipped_values; ++i) {
    bitgen();
  }
  // Cycle through the number of skipped values to so that on average we skip
  // one value on each invocation.
  num_skipped_values = (num_skipped_values + 1) % (kMaxSkippedValues + 1);
}

}  // namespace fuzztest::internal
