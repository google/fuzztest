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

// Tests of domains Map, ReversibleMap, FlatMap, and Filter.

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/algorithm/container.h"
#include "absl/random/random.h"
#include "./fuzztest/domain_core.h"
#include "./domain_tests/domain_testing.h"

namespace fuzztest {
namespace {

using ::testing::Contains;
using ::testing::Each;
using ::testing::Eq;
using ::testing::HasSubstr;
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

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(
      domain_a.ValidateCorpusValue(value_b.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value for Map\(\)-ed domain >> The value .+ is not InRange\(0, 9\))")));
  EXPECT_THAT(
      domain_b.ValidateCorpusValue(value_a.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value for Map\(\)-ed domain >> The value .+ is not InRange\(10, 19\))")));
}

TEST(Map, MapperWorksWithMoveOnlyTypes) {
  auto domain =
      Map([](std::unique_ptr<int> n) -> int { return n == nullptr ? 0 : *n; },
          UniquePtrOf(Just(1)));
  EXPECT_THAT(MutateUntilFoundN(domain, /*n=*/2), UnorderedElementsAre(0, 1));
}

TEST(ReversibleMap, WorksWhenMapFunctionHasSameDomainAndRange) {
  auto domain = ReversibleMap(
      [](int a) { return ~a; },
      [](int a) { return std::optional(std::tuple(~a)); }, Arbitrary<int>());
  absl::BitGen bitgen;
  Value value(domain, bitgen);
  EXPECT_EQ(value.user_value, ~std::get<0>(value.corpus_value));
}

TEST(ReversibleMap, ValidationRejectsInvalidValue) {
  absl::BitGen bitgen;

  auto domain_a = ReversibleMap(
      [](int a) { return ~a; },
      [](int a) { return std::optional(std::tuple(~a)); }, InRange(0, 9));
  auto domain_b = ReversibleMap(
      [](int a) { return ~a; },
      [](int a) { return std::optional(std::tuple(~a)); }, InRange(10, 19));

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(
      domain_a.ValidateCorpusValue(value_b.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value for ReversibleMap\(\)-ed domain >> The value .+ is not InRange\(0, 9\))")));
  EXPECT_THAT(
      domain_b.ValidateCorpusValue(value_a.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value for ReversibleMap\(\)-ed domain >> The value .+ is not InRange\(10, 19\))")));
}

TEST(ReversibleMap, AcceptsMultipleInnerDomains) {
  auto domain = ReversibleMap(
      [](int a, char b) {
        std::string s;
        for (; a > 0; --a) s += b;
        return s;
      },
      [](const std::string& s) {
        return std::optional(std::tuple<int, char>(s.length(), s[0]));
      },
      InRange(2, 4), ElementOf<char>({'A', 'B'}));
  auto all_values = {"AA", "AAA", "AAAA", "BB", "BBB", "BBBB"};
  for (const std::string& s : all_values) {
    ASSERT_TRUE(domain.FromValue(s).has_value());
    EXPECT_EQ(domain.GetValue(domain.FromValue(s).value()), s);
  }
}

TEST(ReversibleMap, WorksWithSeeds) {
  absl::BitGen bitgen;

  auto domain = ReversibleMap([](int a) { return a * 2; },
                              [](int a) -> std::optional<std::tuple<int>> {
                                if (a % 2 == 1) return std::nullopt;
                                return std::optional(std::tuple(a / 2));
                              },
                              InRange(0, 1000000))
                    .WithSeeds({8});

  EXPECT_THAT(GenerateInitialValues(domain, 20), Contains(8));
  EXPECT_THAT(domain.FromValue(7), Eq(std::nullopt));
}

TEST(ReversibleMap, MapperWorksWithMoveOnlyTypes) {
  auto domain = ReversibleMap(
      [](std::unique_ptr<int> n) -> int { return n == nullptr ? 0 : *n; },
      [](int n) -> std::optional<std::tuple<std::unique_ptr<int>>> {
        return {{std::make_unique<int>(n)}};
      },
      UniquePtrOf(Just(1)));
  EXPECT_THAT(MutateUntilFoundN(domain, /*n=*/2), UnorderedElementsAre(0, 1));
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

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(
      domain_a.ValidateCorpusValue(value_b.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value for FlatMap\(\)-ed domain >> The value .+ is not InRange\(0, 9\))")));
  EXPECT_THAT(
      domain_b.ValidateCorpusValue(value_a.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value for FlatMap\(\)-ed domain >> The value .+ is not InRange\(10, 19\))")));
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
    domain.Mutate(mutated, bitgen, {}, false);
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
    domain.Mutate(mutated, bitgen, {}, true);
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
    domain.Mutate(mutated, bitgen, {}, true);
    EXPECT_THAT(domain.GetValue(mutated).size(), Eq(original_size));
  }
  EXPECT_THAT(domain.GetValue(mutated), Each(Eq(0)));
}

TEST(FlatMap, FlatMapperWorksWithMoveOnlyTypes) {
  auto domain = FlatMap(
      [](std::unique_ptr<int> n) -> Domain<int> {
        return n == nullptr ? Just(0) : Just(*n);
      },
      UniquePtrOf(Just(1)));
  EXPECT_THAT(MutateUntilFoundN(domain, /*n=*/2), UnorderedElementsAre(0, 1));
}

TEST(FlatMap, ParseCorpusRejectsInvalidInputValues) {
  absl::BitGen bitgen;

  auto domain_a = FlatMap([](int a) { return Just(a); }, InRange(0, 9));
  auto domain_b = FlatMap([](int a) { return Just(a); }, InRange(10, 19));

  Value value(domain_a, bitgen);
  auto serialized = domain_a.SerializeCorpus(value.corpus_value);

  EXPECT_EQ(domain_b.ParseCorpus(serialized), std::nullopt);
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
    value.Mutate(domain, bitgen, {}, false);
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

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(domain_a.ValidateCorpusValue(value_b.corpus_value),
              IsInvalid("Value does not match Filter() predicate."));
  EXPECT_THAT(domain_b.ValidateCorpusValue(value_a.corpus_value),
              IsInvalid("Value does not match Filter() predicate."));

  Domain<int> wrapped_domain_a = Filter([](int i) { return true; }, domain_a);
  Domain<int> wrapped_domain_b = Filter([](int i) { return true; }, domain_b);

  Value wrapped_value_a(wrapped_domain_a, bitgen);
  Value wrapped_value_b(wrapped_domain_b, bitgen);

  ASSERT_OK(wrapped_domain_a.ValidateCorpusValue(wrapped_value_a.corpus_value));
  ASSERT_OK(wrapped_domain_b.ValidateCorpusValue(wrapped_value_b.corpus_value));

  EXPECT_THAT(
      wrapped_domain_a.ValidateCorpusValue(wrapped_value_b.corpus_value),
      IsInvalid(
          HasSubstr("Invalid corpus value for the inner domain in Filter()")));
  EXPECT_THAT(
      wrapped_domain_b.ValidateCorpusValue(wrapped_value_a.corpus_value),
      IsInvalid(
          HasSubstr("Invalid corpus value for the inner domain in Filter()")));
}

}  // namespace
}  // namespace fuzztest
