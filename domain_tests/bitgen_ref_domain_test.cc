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

#include <cstdint>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"
#include "./fuzztest/domain_core.h"
#include "./domain_tests/domain_testing.h"

namespace fuzztest {
namespace {

TEST(BitGenRefDomainTest, DefaultInitializationIsRepeatable) {
  absl::BitGen bitgen_for_seeding;

  Domain<absl::BitGenRef> domain = Arbitrary<absl::BitGenRef>();
  Value v0(domain, bitgen_for_seeding);

  std::vector<uint64_t> variates;
  for (int i = 0; i < 10; ++i) {
    variates.push_back(v0.user_value());
  }
  // The default domain does not require either data or control streams.
  // So the initial sequences may be the same, but we generally don't expect
  // them all to be the same.
  EXPECT_THAT(variates, testing::Not(testing::Each(testing::Eq(variates[0]))));
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

}  // namespace
}  // namespace fuzztest
