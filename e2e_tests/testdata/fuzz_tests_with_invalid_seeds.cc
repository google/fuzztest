// Copyright 2022 Google LLC
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

// Fuzz test examples to be used by `functional_test` only.

#include "./fuzztest/fuzztest.h"

namespace {

// TODO(b/203465367): Investigate if we can delay execution of seed parsing
// until main().
void InvalidSeedDueToUserValueNotConvertibleToCorpusValue(int) {}
FUZZ_TEST(MySuite, InvalidSeedDueToUserValueNotConvertibleToCorpusValue)
    // Map does not support seeds.
    .WithDomains(fuzztest::Map([](int) { return 0; },
                               fuzztest::Arbitrary<int>()))
    .WithSeeds({{17}});

void InvalidSeedDueToCorpusValueOutOfDomain(int) {}
FUZZ_TEST(MySuite, InvalidSeedDueToCorpusValueOutOfDomain)
    .WithDomains(fuzztest::InRange(0, 10))
    .WithSeeds({{2}, {17}, {6}});

struct MyTest {
  void ShouldNotCrash(int) {}
  std::vector<std::tuple<int>> GetSeeds() { return {{2}, {17}, {6}}; }
};
FUZZ_TEST_F(MyTest, ShouldNotCrash)
    .WithDomains(fuzztest::InRange(0, 10))
    .WithSeeds(&MyTest::GetSeeds);

}  // namespace
