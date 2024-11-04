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

// Tests of various domains that don't fit naturally into the other test files
// in this directory: BitFlagCombinationOf, OneOf, and OverlapOf.

#include <cstdlib>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/numeric/int128.h"
#include "absl/random/random.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/types/span.h"
#include "./fuzztest/domain_core.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest {
namespace internal {

class OverlapOfTestPeer {
 public:
  template <typename D>
  static void SetSerializationDomain(D& domain, size_t index) {
    domain.WithSerializationDomain(index);
  }
};

}  // namespace internal

namespace {

using ::testing::AllOf;
using ::testing::Contains;
using ::testing::Each;
using ::testing::Ge;
using ::testing::IsSupersetOf;
using ::testing::Le;
using ::testing::UnorderedElementsAre;
using ::testing::UnorderedElementsAreArray;

TEST(BitFlagCombinationOf, InitGeneratesSeeds) {
  auto domain = BitFlagCombinationOf({1, 4, 16, 32}).WithSeeds({5, 17});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              AllOf(Contains(Value(domain, 5)), Contains(Value(domain, 17))));
}

TEST(BitFlagCombinationOf, Ints) {
  auto domain = BitFlagCombinationOf({1, 4, 16, 32});
  auto seen = MutateUntilFoundN(domain, 16);
  EXPECT_THAT(seen, UnorderedElementsAre(0, 1, 4, 5, 16, 17, 20, 21, 32, 33, 36,
                                         37, 48, 49, 52, 53));

  absl::BitGen bitgen;
  int val = 1 | 4 | 16 | 32;
  while (val != 0) {
    int prev = val;
    domain.Mutate(val, bitgen, {}, true);
    // val can't have new bits set.
    EXPECT_EQ(prev & val, val);
    EXPECT_EQ(prev | val, prev);
  }
}

TEST(BitFlagCombinationOf, Enum) {
  enum class E { A = 1, B = 8 };
  auto domain = BitFlagCombinationOf({E::A, E::B});

  auto seen = MutateUntilFoundN(domain, 4);
  EXPECT_THAT(seen, UnorderedElementsAre(E{0}, E{1}, E{8}, E{9}));
}

TEST(BitFlagCombinationOf, UserDefined) {
  EXPECT_THAT(
      MutateUntilFoundN(
          BitFlagCombinationOf({absl::uint128(1), absl::uint128(4)}), 4),
      UnorderedElementsAre(absl::uint128(0), absl::uint128(1), absl::uint128(4),
                           absl::uint128(5)));
}

TEST(BitFlagCombinationOf, InvalidInputReportsErrors) {
  EXPECT_DEATH_IF_SUPPORTED(BitFlagCombinationOf<int>({}),
                            "BitFlagCombinationOf requires a non empty list.");

  EXPECT_DEATH_IF_SUPPORTED(BitFlagCombinationOf({0, 1, 2}),
                            "BitFlagCombinationOf requires non zero flags.");

  EXPECT_DEATH_IF_SUPPORTED(
      BitFlagCombinationOf({1, 2, 3}),
      "BitFlagCombinationOf requires flags to be mutually exclusive.");
}

TEST(BitFlagCombinationOf, ValidationRejectsInvalidValue) {
  auto domain = BitFlagCombinationOf({1, 4});
  EXPECT_OK(domain.ValidateCorpusValue(0));
  EXPECT_OK(domain.ValidateCorpusValue(1));
  EXPECT_OK(domain.ValidateCorpusValue(4));
  EXPECT_OK(domain.ValidateCorpusValue(5));
  EXPECT_THAT(domain.ValidateCorpusValue(2),
              IsInvalid("Invalid bit flag combination."));
  EXPECT_THAT(domain.ValidateCorpusValue(17),
              IsInvalid("Invalid bit flag combination."));
}

TEST(OneOf, InitGeneratesSeeds) {
  auto domain = OneOf(Negative<int>(), Positive<int>()).WithSeeds({-42, 42});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              AllOf(Contains(Value(domain, -42)), Contains(Value(domain, 42))));
}

TEST(OneOf, AllSubDomainsArePickedEventually) {
  absl::BitGen bitgen;
  std::vector<int> vals;
  for (int i = 1; i <= 5; ++i) {
    vals.push_back(i);
  }
  auto domain = OneOf(Just(1), Just(2), Just(3), Just(4), Just(5));

  absl::flat_hash_set<int> elems;
  while (elems.size() < 5) {
    Value inited(domain, bitgen);
    elems.insert(inited.user_value);
  }
  ASSERT_THAT(elems, UnorderedElementsAreArray(vals));

  elems.clear();
  Value mutated(domain, bitgen);
  while (elems.size() < 5) {
    mutated.Mutate(domain, bitgen, {}, false);
    elems.insert(mutated.user_value);

    VerifyRoundTripThroughConversion(mutated, domain);
  }
  ASSERT_THAT(elems, UnorderedElementsAreArray(vals));
}

TEST(OneOf, Mutate) {
  absl::BitGen bitgen;
  constexpr int kRuns = 100;
  constexpr int kMax = 1000;
  auto domain = OneOf(InRange(-kMax, -1), InRange(0, kMax));
  for (int i = 0; i < kRuns; ++i) {
    int k = absl::Uniform(bitgen, -kMax, kMax);
    Value v(domain, bitgen);
    // Construct the internal corpus_type representation from the integer.
    if (k < 0) {
      v.corpus_value = std::variant<int, int>(std::in_place_index_t<0>{}, k);
    } else {
      v.corpus_value = std::variant<int, int>(std::in_place_index_t<1>{}, k);
    }
    v.Mutate(domain, bitgen, {}, false);
    ASSERT_NE(k, v.user_value);
  }
  for (int i = 0; i < kRuns; ++i) {
    Value v(domain, bitgen);
    int old_k = v.user_value;
    v.Mutate(domain, bitgen, {}, true);
    int new_k = v.user_value;
    if ((new_k >= 0) == (old_k >= 0)) {
      EXPECT_LE(std::abs(new_k), std::abs(old_k))
          << "Values (run " << i << "): " << new_k << " <= " << old_k;
    }
  }
}

enum class Color : int { Red, Green, Blue, Yellow };

TEST(OneOf, SwitchesDomains) {
  absl::BitGen bitgen;
  std::vector<Color> all_colors{Color::Red, Color::Green, Color::Blue,
                                Color::Yellow};
  auto domain = OneOf(ElementOf({Color::Red, Color::Green}),
                      ElementOf({Color::Blue, Color::Yellow}));
  absl::flat_hash_set<Color> found;
  Value v(domain, bitgen);
  while (found.size() < all_colors.size()) {
    v.Mutate(domain, bitgen, {}, false);
    found.insert(v.user_value);
  }
  ASSERT_THAT(found, UnorderedElementsAreArray(all_colors));
}

TEST(OneOf, ValidationRejectsInvalidValue) {
  absl::BitGen bitgen;

  auto domain_a = OneOf(InRange(0, 3), InRange(5, 7));
  auto domain_b = OneOf(InRange(10, 12), InRange(15, 17));

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(
      domain_a.ValidateCorpusValue(value_b.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value for OneOf\(\) domain >> The value .+ is not InRange(.+))")));
  EXPECT_THAT(
      domain_b.ValidateCorpusValue(value_a.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value for OneOf\(\) domain >> The value .+ is not InRange(.+))")));
}

TEST(OneOf, FromValueReturnsValidCorpusValuesWhenPossible) {
  auto domain = OneOf(InRange(0, 3), InRange(5, 7));
  auto corpus_value = domain.FromValue(6);

  ASSERT_TRUE(corpus_value.has_value());
  EXPECT_OK(domain.ValidateCorpusValue(*corpus_value));
}

TEST(OverlapOf, ValidatesForAllDomains) {
  auto domain = OverlapOf(InRange(0, 3), InRange(1, 4));
  EXPECT_FALSE(domain.FromValue(0).has_value());
  EXPECT_TRUE(domain.FromValue(1).has_value());
  EXPECT_TRUE(domain.FromValue(2).has_value());
  EXPECT_TRUE(domain.FromValue(3).has_value());
  EXPECT_FALSE(domain.FromValue(4).has_value());
}

TEST(OverlapOf, GeneratesMultipleValidValues) {
  auto domain = OverlapOf(InRange(0, 3), InRange(1, 4));
  EXPECT_THAT(GenerateNonUniqueValues(domain),
              AllOf(Each(AllOf(Ge(1), Le(3))), IsSupersetOf({1, 2, 3})));
}

TEST(OverlapOf, UsesSerializationDomain) {
  auto domain_0 = Arbitrary<std::string>();
  auto domain_1 =
      ReversibleMap([](int x) -> std::string { return absl::StrCat(x); },
                    [](const std::string& s) -> std::optional<std::tuple<int>> {
                      int result = 0;
                      if (!absl::SimpleAtoi(s, &result)) return std::nullopt;
                      return result;
                    },
                    Arbitrary<int>());
  auto overlapped_domain = OverlapOf(domain_0, domain_1);
  for (const auto& v : GenerateNonUniqueValues(overlapped_domain)) {
    auto domain_0_corpus = domain_0.FromValue(v.user_value);
    ASSERT_TRUE(domain_0_corpus.has_value());
    auto domain_1_corpus = domain_1.FromValue(v.user_value);
    ASSERT_TRUE(domain_1_corpus.has_value());
    EXPECT_NE(overlapped_domain.SerializeCorpus(v.corpus_value).ToString(),
              domain_0.SerializeCorpus(*domain_0_corpus).ToString())
        << "Expect different serialized corpora before "
           "`WithSerializationDomain(...)`";
    EXPECT_NE(overlapped_domain.SerializeCorpus(v.corpus_value).ToString(),
              domain_1.SerializeCorpus(*domain_1_corpus).ToString())
        << "Expect different serialized corpora before "
           "`WithSerializationDomain(...)`";
  }

  internal::OverlapOfTestPeer::SetSerializationDomain(overlapped_domain, 0);
  for (const auto& v : GenerateNonUniqueValues(overlapped_domain)) {
    auto domain_0_corpus = domain_0.FromValue(v.user_value);
    ASSERT_TRUE(domain_0_corpus.has_value());
    auto domain_1_corpus = domain_1.FromValue(v.user_value);
    ASSERT_TRUE(domain_1_corpus.has_value());
    EXPECT_EQ(overlapped_domain.SerializeCorpus(v.corpus_value).ToString(),
              domain_0.SerializeCorpus(*domain_0_corpus).ToString())
        << "Expect the same serialized corpora after "
           "`WithSerializationDomain(0)`";
    EXPECT_NE(overlapped_domain.SerializeCorpus(v.corpus_value).ToString(),
              domain_1.SerializeCorpus(*domain_1_corpus).ToString())
        << "Expect different serialized corpora after "
           "`WithSerializationDomain(0)`";
  }

  internal::OverlapOfTestPeer::SetSerializationDomain(overlapped_domain, 1);
  for (const auto& v : GenerateNonUniqueValues(overlapped_domain)) {
    auto domain_0_corpus = domain_0.FromValue(v.user_value);
    ASSERT_TRUE(domain_0_corpus.has_value());
    auto domain_1_corpus = domain_1.FromValue(v.user_value);
    ASSERT_TRUE(domain_1_corpus.has_value());
    EXPECT_NE(overlapped_domain.SerializeCorpus(v.corpus_value).ToString(),
              domain_0.SerializeCorpus(*domain_0_corpus).ToString())
        << "Expect different serialized corpora after "
           "`WithSerializationDomain(1)`";
    EXPECT_EQ(overlapped_domain.SerializeCorpus(v.corpus_value).ToString(),
              domain_1.SerializeCorpus(*domain_1_corpus).ToString())
        << "Expect the same serialized corpora after "
           "`WithSerializationDomain(1)`";
  }
}

}  // namespace
}  // namespace fuzztest

// This is outside the fuzztest namespace on purpose to avoid the lexical scope.
namespace {

TEST(Domain, DoesNotTriggerADL) {
  // If ADL triggered the expression `StringOf(x)` will be valid.
  // We expect that it is not valid.
  EXPECT_FALSE(fuzztest::internal::Requires<fuzztest::Domain<char>>(
      [](auto x) -> decltype(StringOf(x)) {}));

  // Qualified is ok.
  EXPECT_TRUE(fuzztest::internal::Requires<fuzztest::Domain<char>>(
      [](auto x) -> decltype(fuzztest::StringOf(x)) {}));

  // And importing the name is ok too.
  using fuzztest::StringOf;
  EXPECT_TRUE(fuzztest::internal::Requires<fuzztest::Domain<char>>(
      [](auto x) -> decltype(StringOf(x)) {}));
}

}  // namespace
