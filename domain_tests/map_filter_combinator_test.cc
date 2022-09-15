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

// Tests of domains Map and Filter.

#include <bitset>
#include <cctype>
#include <deque>
#include <iterator>
#include <list>
#include <optional>
#include <set>
#include <string>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "googlemock/include/gmock/gmock.h"
#include "googletest/include/gtest/gtest.h"
#include "absl/random/random.h"
#include "./fuzztest/domain.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest {
namespace {

using ::testing::UnorderedElementsAre;

TEST(Map, WorksWithSameCorpusType) {
  auto domain = Map([](int a) { return ~a; }, Arbitrary<int>());
  absl::BitGen bitgen;
  Value value(domain, bitgen);
  EXPECT_EQ(value.user_value, ~std::get<0>(value.corpus_value));
}

enum class Color : int { Red, Green, Blue, Yellow };

TEST(Map, WorksWithDifferentCorpusType) {
  auto colors = ElementOf({Color::Blue});
  auto domain = Map(
      [](Color a) -> std::string { return a == Color::Blue ? "Blue" : "None"; },
      colors);
  absl::BitGen bitgen;
  Value value(domain, bitgen);
  // `0` is the index in the ElementOf
  EXPECT_EQ(typename decltype(colors)::corpus_type{0},
            std::get<0>(value.corpus_value));
  EXPECT_EQ("Blue", value.user_value);
}

TEST(Map, AcceptsMultipleInnerDomains) {
  auto domain = Map(
      [](int a, std::string_view b) {
        std::string s;
        for (; a > 0; --a) s += b;
        return s;
      },
      InRange(2, 4), ElementOf<std::string_view>({"A", "B"}));
  absl::BitGen bitgen;
  Set<std::string> values;
  while (values.size() < 6) {
    values.insert(Value(domain, bitgen).user_value);
  }
  EXPECT_THAT(values,
              UnorderedElementsAre("AA", "AAA", "AAAA", "BB", "BBB", "BBBB"));
}

TEST(Filter, CanFilterInitCalls) {
  Domain<int> domain = Filter([](int i) { return i % 2 == 0; }, InRange(1, 10));
  absl::BitGen bitgen;
  Set<int> seen;
  while (seen.size() < 5) {
    seen.insert(Value(domain, bitgen).user_value);
  }
  EXPECT_THAT(seen, UnorderedElementsAre(2, 4, 6, 8, 10));
}

TEST(Filter, CanFilterMutateCalls) {
  Domain<int> domain = Filter([](int i) { return i % 2 == 0; }, InRange(1, 10));
  absl::BitGen bitgen;
  Value value(domain, bitgen);
  Set<int> seen;
  while (seen.size() < 5) {
    value.Mutate(domain, bitgen, false);
    seen.insert(value.user_value);
  }
  EXPECT_THAT(seen, UnorderedElementsAre(2, 4, 6, 8, 10));
}

TEST(Filter, CanRoundTripConversions) {
  Domain<int> domain =
      Filter([](int i) { return i % 2 == 0; }, ElementOf({1, 2, 3, 4}));
  absl::BitGen bitgen;
  Value value(domain, bitgen);
  VerifyRoundTripThroughConversion(value, domain);
}

}  // namespace
}  // namespace fuzztest
