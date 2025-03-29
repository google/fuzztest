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

#include "gtest/gtest.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"
#include "./fuzztest/domain_core.h"
#include "./domain_tests/domain_testing.h"

namespace fuzztest {
namespace {

TEST(BitGenRefDomainTest, Basic) {
  absl::BitGen bitgen;
  Domain<absl::BitGenRef> domain = Arbitrary<absl::BitGenRef>();

  // Two values which are initialized differently are actually different.
  Value v0(domain, bitgen);
  Value v1(domain, bitgen);
  int equal = 0;
  for (int i = 0; i < 10; ++i) {
    equal += (v0.user_value() == v1.user_value());
  }
  EXPECT_NE(equal, 10);
}

}  // namespace
}  // namespace fuzztest
