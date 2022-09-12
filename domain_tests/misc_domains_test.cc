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
// in this directory: BitFlagCombinationOf and OneOf.

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
#include "absl/container/flat_hash_set.h"
#include "absl/numeric/int128.h"
#include "absl/random/random.h"
#include "./fuzztest/domain.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/meta.h"

namespace fuzztest {
namespace {

using ::testing::UnorderedElementsAre;
using ::testing::UnorderedElementsAreArray;

TEST(BitFlagCombinationOf, Ints) {
  auto domain = BitFlagCombinationOf({1, 4, 16, 32});
  auto seen = MutateUntilFoundN(domain, 16);
  EXPECT_THAT(seen, UnorderedElementsAre(0, 1, 4, 5, 16, 17, 20, 21, 32, 33, 36,
                                         37, 48, 49, 52, 53));

  absl::BitGen bitgen;
  int val = 1 | 4 | 16 | 32;
  while (val != 0) {
    int prev = val;
    domain.Mutate(val, bitgen, true);
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

  EXPECT_THAT(
      MutateUntilFoundN(
          BitFlagCombinationOf({std::bitset<10>(2), std::bitset<10>(16)}), 4),
      UnorderedElementsAre(std::bitset<10>(0), std::bitset<10>(2),
                           std::bitset<10>(16), std::bitset<10>(18)));
}

TEST(BitFlagCombinationOf, InvalidInputReportsErrors) {
  EXPECT_DEATH_IF_SUPPORTED(
      BitFlagCombinationOf<int>({}),
      "domain.h:.*Failed precondition .!flags.empty...: BitFlagCombinationOf "
      "requires a non empty list.");

  EXPECT_DEATH_IF_SUPPORTED(BitFlagCombinationOf({0, 1, 2}),
                            "BitFlagCombinationOf requires non zero flags.");

  EXPECT_DEATH_IF_SUPPORTED(
      BitFlagCombinationOf({1, 2, 3}),
      "BitFlagCombinationOf requires flags to be mutually exclusive.");
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
    mutated.Mutate(domain, bitgen, false);
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
    v.Mutate(domain, bitgen, /*only_shrink=*/false);
    ASSERT_NE(k, v.user_value);
  }
  for (int i = 0; i < kRuns; ++i) {
    Value v(domain, bitgen);
    int old_k = v.user_value;
    v.Mutate(domain, bitgen, /*only_shrink=*/true);
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
    v.Mutate(domain, bitgen, /*only_shrink=*/false);
    found.insert(v.user_value);
  }
  ASSERT_THAT(found, UnorderedElementsAreArray(all_colors));
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
