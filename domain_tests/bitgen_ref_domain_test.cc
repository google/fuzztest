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

#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
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

  // Initialize a set of bitgen references.
  std::vector<decltype(Value(domain, bitgen_for_seeding))> values;
  values.reserve(10);
  for (int i = 0; i < 10; ++i) {
    values.emplace_back(domain, bitgen_for_seeding);
  }

  // Some of the "randomly initialized" streams should be different.
  for (int i = 0; i < 10; ++i) {
    absl::flat_hash_set<absl::BitGenRef::result_type> s;
    for (auto& v : values) {
      s.insert(v.user_value());
    }
    EXPECT_NE(s.size(), 1) << *s.begin();
  }
}

TEST(BitGenRefDomainTest, AbseilUniformIsFunctionalWhenExhausted) {
  absl::BitGen bitgen_for_seeding;

  Domain<absl::BitGenRef> domain = Arbitrary<absl::BitGenRef>();
  Value v0(domain, bitgen_for_seeding);
  Value v1(v0, domain);

  // When the same domain is used to generate multiple values, the generated
  // data sequence should be identical.
  std::vector<int> values;
  for (int i = 0; i < 100; ++i) {
    EXPECT_EQ(absl::Uniform<int>(v0.user_value, 0, 100),
              absl::Uniform<int>(v1.user_value, 0, 100))
        << i;
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

}  // namespace
}  // namespace fuzztest
