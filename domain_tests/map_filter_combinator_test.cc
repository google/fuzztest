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

// Tests of domains Map, FlatMap, and Filter.

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/algorithm/container.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/random.h"
#include "absl/types/span.h"
#include "./fuzztest/domain.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest {
namespace {

using ::testing::Contains;
using ::testing::Each;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::UnorderedElementsAre;

TEST(Map, WorksWhenMapFunctionHasSameDomainAndRange) {
  auto domain = Map([](int a) { return ~a; }, Arbitrary<int>());
  absl::BitGen bitgen;
  Value value(domain, bitgen);
  EXPECT_EQ(value.user_value, ~std::get<0>(value.corpus_value));
}

enum class Color : int { Red, Green, Blue, Yellow };

TEST(Map, WorksWhenMapFunctionHasDifferentDomainAndRange) {
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

TEST(Map, ValidationRejectsInvalidValue) {
  absl::BitGen bitgen;

  auto domain_a = Map([](int a) { return ~a; }, InRange(0, 9));
  auto domain_b = Map([](int a) { return ~a; }, InRange(10, 19));

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_TRUE(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_TRUE(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_FALSE(domain_a.ValidateCorpusValue(value_b.corpus_value));
  EXPECT_FALSE(domain_b.ValidateCorpusValue(value_a.corpus_value));
}

TEST(BidiMap, WorksWhenMapFunctionHasSameDomainAndRange) {
  auto domain =
      internal::BidiMap([](int a) { return ~a; },
                        [](int a) { return std::tuple(~a); }, Arbitrary<int>());
  absl::BitGen bitgen;
  Value value(domain, bitgen);
  EXPECT_EQ(value.user_value, ~std::get<0>(value.corpus_value));
}

TEST(BidiMap, ValidationRejectsInvalidValue) {
  absl::BitGen bitgen;

  auto domain_a =
      internal::BidiMap([](int a) { return ~a; },
                        [](int a) { return std::tuple(~a); }, InRange(0, 9));
  auto domain_b =
      BidiMap([](int a) { return ~a; }, [](int a) { return std::tuple(~a); },
              InRange(10, 19));

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_TRUE(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_TRUE(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_FALSE(domain_a.ValidateCorpusValue(value_b.corpus_value));
  EXPECT_FALSE(domain_b.ValidateCorpusValue(value_a.corpus_value));
}

TEST(BidiMap, AcceptsMultipleInnerDomains) {
  auto domain = internal::BidiMap(
      [](int a, char b) {
        std::string s;
        for (; a > 0; --a) s += b;
        return s;
      },
      [](const std::string& s) {
        return std::tuple<int, char>(s.length(), s[0]);
      },
      InRange(2, 4), ElementOf<char>({'A', 'B'}));
  auto all_values = {"AA", "AAA", "AAAA", "BB", "BBB", "BBBB"};
  for (const std::string& s : all_values) {
    ASSERT_TRUE(domain.FromValue(s).has_value());
    EXPECT_EQ(domain.GetValue(domain.FromValue(s).value()), s);
  }
}

TEST(BidiMap, WorksWithSeeds) {
  absl::BitGen bitgen;

  auto domain = internal::BidiMap([](int a) { return a + 1; },
                                  [](int a) { return std::tuple(a - 1); },
                                  InRange(0, 1000000))
                    .WithSeeds({7});

  EXPECT_THAT(GenerateInitialValues(domain, 20), Contains(7));
}

TEST(FlatMap, WorksWithSameCorpusType) {
  auto domain = FlatMap([](int a) { return Just(~a); }, Arbitrary<int>());
  absl::BitGen bitgen;
  Value value(domain, bitgen);
  EXPECT_EQ(value.user_value, ~std::get<1>(value.corpus_value));
}

TEST(FlatMap, WorksWithDifferentCorpusType) {
  auto colors = Just(Color::Blue);
  auto domain = FlatMap(
      [](Color a) {
        std::string s = a == Color::Blue ? "Blue" : "None";
        return Just(s);
      },
      colors);
  absl::BitGen bitgen;
  Value value(domain, bitgen);
  // `0` is the index in the ElementOf
  EXPECT_EQ(typename decltype(colors)::corpus_type{0},
            std::get<1>(value.corpus_value));
  EXPECT_EQ("Blue", value.user_value);
}

TEST(FlatMap, AcceptsMultipleInnerDomains) {
  auto domain =
      FlatMap([](int len, char c) { return StringOf(Just(c)).WithSize(len); },
              InRange(2, 4), ElementOf({'A', 'B'}));
  absl::BitGen bitgen;
  Set<std::string> values;
  while (values.size() < 6) {
    values.insert(Value(domain, bitgen).user_value);
  }
  EXPECT_THAT(values,
              UnorderedElementsAre("AA", "AAA", "AAAA", "BB", "BBB", "BBBB"));
}

TEST(FlatMap, SerializationRoundTrip) {
  auto domain = FlatMap([](int len) { return AsciiString().WithSize(len); },
                        InRange(0, 10));
  absl::BitGen bitgen;
  Value value(domain, bitgen);
  auto serialized = domain.SerializeCorpus(value.corpus_value);
  EXPECT_EQ(domain.ParseCorpus(serialized), value.corpus_value);
}

TEST(FlatMap, ValidationRejectsInvalidValue) {
  absl::BitGen bitgen;

  auto domain_a = FlatMap([](int a) { return Just(~a); }, InRange(0, 9));
  auto domain_b = FlatMap([](int a) { return Just(~a); }, InRange(10, 19));

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_TRUE(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_TRUE(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_FALSE(domain_a.ValidateCorpusValue(value_b.corpus_value));
  EXPECT_FALSE(domain_b.ValidateCorpusValue(value_a.corpus_value));
}

TEST(FlatMap, MutationAcceptsChangingDomains) {
  auto domain = FlatMap([](int len) { return AsciiString().WithSize(len); },
                        InRange(0, 10));
  absl::BitGen bitgen;
  Value value(domain, bitgen);
  auto mutated = value.corpus_value;
  while (std::get<1>(value.corpus_value) == std::get<1>(mutated)) {
    // We demand that our output domain has size `len` above. This will check
    // fail in ContainerOfImpl if we try to generate a string of the wrong
    // length.
    domain.Mutate(mutated, bitgen, false);
  }
  EXPECT_EQ(domain.GetValue(mutated).size(), std::get<1>(mutated));
}

TEST(FlatMap, MutationAcceptsShrinkingOutputDomains) {
  auto domain = FlatMap([](int len) { return AsciiString().WithMaxSize(len); },
                        InRange(0, 10));
  absl::BitGen bitgen;
  std::optional<Value<decltype(domain)>> value;
  // Generate something shrinkable
  while (!value.has_value() || value->user_value.empty()) {
    value = Value(domain, bitgen);
  }
  auto mutated = value->corpus_value;
  while (!domain.GetValue(mutated).empty()) {
    domain.Mutate(mutated, bitgen, true);
  }
  EXPECT_THAT(domain.GetValue(mutated), IsEmpty());
}

TEST(FlatMap, MutationDoesNotAlterInputDomains) {
  auto domain =
      FlatMap([](int len) { return VectorOf(Arbitrary<int>()).WithSize(len); },
              InRange(5, 10));
  absl::BitGen bitgen;
  std::optional<Value<decltype(domain)>> value;
  // Generate something shrinkable
  auto all_zeros = [](const std::vector<int>& v) {
    return absl::c_all_of(v, [](int x) { return x == 0; });
  };
  while (!value.has_value() || all_zeros(value->user_value)) {
    value = Value(domain, bitgen);
  }
  auto mutated = value->corpus_value;
  const size_t original_size = value->user_value.size();
  while (!all_zeros(domain.GetValue(mutated))) {
    domain.Mutate(mutated, bitgen, true);
    EXPECT_THAT(domain.GetValue(mutated).size(), Eq(original_size));
  }
  EXPECT_THAT(domain.GetValue(mutated), Each(Eq(0)));
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

TEST(Filter, InitGeneratesSeeds) {
  auto domain = Filter([](int i) { return i % 2 == 0; }, Arbitrary<int>())
                    .WithSeeds({42});

  EXPECT_THAT(GenerateInitialValues(domain, 1000), Contains(Value(domain, 42)));
}

TEST(Filter, WithSeedsFailsWhenConversionFromUserValueFails) {
  EXPECT_DEATH_IF_SUPPORTED(
      Filter([](int i) { return i % 2 == 0; }, Arbitrary<int>())
          .WithSeeds({41}),
      "Invalid seed value");
}

TEST(Filter, ValidationRejectsInvalidValue) {
  absl::BitGen bitgen;

  Domain<int> domain_a =
      Filter([](int i) { return i % 2 == 0; }, InRange(1, 10));
  Domain<int> domain_b =
      Filter([](int i) { return i % 2 != 0; }, InRange(1, 10));

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_TRUE(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_TRUE(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_FALSE(domain_a.ValidateCorpusValue(value_b.corpus_value));
  EXPECT_FALSE(domain_b.ValidateCorpusValue(value_a.corpus_value));
}

}  // namespace
}  // namespace fuzztest
