// Copyright 2025 Google LLC
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

#include <algorithm>
#include <cstddef>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"
#include "./fuzztest/domain_core.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/printer.h"

namespace fuzztest {
namespace {

TEST(BitGenRefDomainTest, DistinctVariatesGeneratedByCallOperator) {
  absl::BitGen bitgen_for_seeding;

  Domain<absl::BitGenRef> domain = Arbitrary<absl::BitGenRef>();
  Value v0(domain, bitgen_for_seeding);
  Value v1(domain, bitgen_for_seeding);

  std::vector<absl::BitGenRef::result_type> a, b;
  for (int i = 0; i < 10; ++i) {
    a.push_back(v0.user_value());
    b.push_back(v1.user_value());
  }

  // These streams should be different, except in very rare cases.
  EXPECT_NE(a, b);
}

TEST(BitGenRefDomainTest, AbseilUniformIsFunctionalWhenExhausted) {
  absl::BitGen bitgen_for_seeding;

  Domain<absl::BitGenRef> domain = Arbitrary<absl::BitGenRef>();
  Value v0(domain, bitgen_for_seeding);

  // When the same domain is used to generate multiple values, the generated
  // data sequence should be identical.
  std::vector<int> values;
  for (int i = 0; i < 20; ++i) {
    values.push_back(absl::Uniform<int>(v0.user_value, 0, 100));
  }

  // Verify repeatability
  Value v1(v0, domain);
  for (int i = 0; i < 20; ++i) {
    EXPECT_EQ(absl::Uniform<int>(v1.user_value, 0, 100), values[i]);
  }
}

TEST(BitGenRefDomainTest, IsPrintable) {
  absl::BitGen bitgen_for_seeding;

  Domain<absl::BitGenRef> domain = Arbitrary<absl::BitGenRef>();
  Value v0(domain, bitgen_for_seeding);

  // Print corpus value
  std::string s;
  domain.GetPrinter().PrintCorpusValue(
      v0.corpus_value, &s, domain_implementor::PrintMode::kHumanReadable);
  EXPECT_THAT(s, testing::StartsWith("FuzzingBitGen"));
}

TEST(BitGenRefDomainTest, MutateUntilSorted) {
  absl::BitGen bitgen_for_seeding;
  std::vector<int> vec;

  // There are 5! possible permutations (120) of the 5-element vector. If
  // FuzzingBitGen generated completely random values, then the likelihood
  // that looping 10k times would not find a sorted permutation is
  // approximately e^(-10000/120).
  // However the `Mutate` operation does not generate an entirely new prng
  // sequence, so we reset the value every 10 iterations instead.
  int count = 0;
  [&]() {
    while (count < 10000) {
      auto domain = Arbitrary<absl::BitGenRef>();
      Value fuzz_rng(domain, bitgen_for_seeding);
      vec = {5, 4, 1, 3, 2};

      for (size_t j = 0; j < 10; ++j) {
        count++;
        std::shuffle(vec.begin(), vec.end(), fuzz_rng.user_value);
        if (std::is_sorted(vec.begin(), vec.end())) return;
        fuzz_rng.Mutate(domain, bitgen_for_seeding, {}, false);
      }
    }
  }();

  EXPECT_TRUE(std::is_sorted(vec.begin(), vec.end()));
}

}  // namespace
}  // namespace fuzztest
