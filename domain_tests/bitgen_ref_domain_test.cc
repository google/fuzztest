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

#include <vector>

#include "gtest/gtest.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"
#include "./fuzztest/domain_core.h"
#include "./domain_tests/domain_testing.h"

namespace fuzztest {
namespace {

TEST(BitGenRefDomainTest, DistinctVariatesGeneratedByCallOperator) {
  absl::BitGen bitgen_for_seeding;

  Domain<absl::BitGenRef> domain = Arbitrary<absl::BitGenRef>();
  Value v0(domain, bitgen_for_seeding);
  Value v1(domain, bitgen_for_seeding);

  // Discard the first value, which may be from the data stream.
  // If the implementation of BitGenRefDomain changes this may break.
  v0.user_value();
  v1.user_value();

  std::vector<absl::BitGenRef::result_type> a, b;
  for (int i = 0; i < 10; ++i) {
    a.push_back(v0.user_value());
    b.push_back(v1.user_value());
  }
  EXPECT_NE(a, b);
}

TEST(BitGenRefDomainTest, AbseilUniformReturnsLowerBoundWhenExhausted) {
  absl::BitGen bitgen_for_seeding;

  Domain<absl::BitGenRef> domain = Arbitrary<absl::BitGenRef>();
  Value v0(domain, bitgen_for_seeding);

  // Discard the first value, which may be from the data stream.
  // If the implementation of BitGenRefDomain changes this may break.
  v0.user_value();

  for (int i = 0; i < 10; ++i) {
    EXPECT_EQ(absl::Uniform<int>(v0.user_value, 0, 100), 0);
  }
}

}  // namespace
}  // namespace fuzztest
