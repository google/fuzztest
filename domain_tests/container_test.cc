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

// Tests of domain ContainerOf, and various shorthands such as VectorOf.

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <list>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/random.h"
#include "./fuzztest/domain_core.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/table_of_recent_compares.h"

namespace fuzztest {
namespace {

using ::testing::Contains;
using ::testing::Gt;
using ::testing::Not;
using ::testing::SizeIs;
using ::testing::UnorderedElementsAre;

template <typename T>
class ContainerTest : public testing::Test {};

using ContainerTypes = testing::Types<
    // Simple types
    std::string, std::vector<int>, std::deque<int>, std::vector<std::byte>,
    // Nested types
    std::vector<std::string>, std::list<std::vector<int>>,
    // Sets
    std::set<int>, std::unordered_set<std::string>, absl::flat_hash_set<int>,
    // Maps
    std::map<int, int>, std::unordered_map<int, int>,
    absl::flat_hash_map<std::string, int>>;

TYPED_TEST_SUITE(ContainerTest, ContainerTypes, );

TYPED_TEST(ContainerTest, Arbitrary) {
  using T = TypeParam;
  Domain<T> domain = Arbitrary<T>();

  auto values = GenerateValues(domain);
  VerifyRoundTripThroughConversion(values, domain);

  // Since we are randomly generating values, we might miss the checks every now
  // and then. In those cases, just make more values.
  for (;; values.merge(GenerateValues(domain))) {
    // Basic checks to make sure we have a few sizes and values.
    // TODO: Check these values in a more principled way.
    absl::flat_hash_map<size_t, size_t> size_distribution;
    absl::flat_hash_map<typename T::value_type, size_t> value_distribution;
    for (const auto& s : values) {
      ++size_distribution[s.user_value.size()];
      for (const auto& v : s.user_value) ++value_distribution[v];
    }
    if (size_distribution.size() <= 10) {
      fprintf(stderr, "Size distribution not met, retrying: %s\n",
              testing::PrintToString(size_distribution).c_str());
      continue;
    }

    if (value_distribution.size() <= 100) {
      fprintf(stderr, "Value distribution not met, retrying: %s\n",
              testing::PrintToString(value_distribution).c_str());
      continue;
    }

    break;
  }

  TestShrink(domain, values, TowardsZero<T>);
}

template <typename Domain>
void TestMinMaxContainerSize(Domain domain, size_t min_size, size_t max_size) {
  absl::BitGen bitgen;

  absl::flat_hash_set<size_t> sizes;

  for (int i = 0; i < 100; ++i) {
    Value v(domain, bitgen);
    auto size_match = SizeIs(IsInClosedRange(min_size, max_size));

    ASSERT_THAT(v.user_value, size_match);
    sizes.insert(v.user_value.size());
    v.Mutate(domain, bitgen, {}, false);
    ASSERT_THAT(v.user_value, size_match);

    // Mutating the value can reach the max, but only for small max sizes
    // because it would otherwise take too long.
    if (max_size <= 10) {
      auto max_v = v;
      while (max_v.user_value.size() < max_size) {
        v.Mutate(domain, bitgen, {}, false);
        if (v.user_value.size() > max_v.user_value.size()) {
          max_v = v;
        } else if (v.user_value.size() < max_v.user_value.size()) {
          // Keep the maximum on `v` to speed up reaching max_size.
          v = max_v;
        }
      }
    }

    // Shinking the value will reach the min.
    while (v.user_value.size() > min_size) {
      v.Mutate(domain, bitgen, {}, true);
    }
    // Mutating again won't go below.
    v.Mutate(domain, bitgen, {}, true);
    ASSERT_THAT(v.user_value, SizeIs(min_size));
  }
  // Check that there is some in between.
  if (min_size == max_size) {
    EXPECT_THAT(sizes, UnorderedElementsAre(min_size));
  } else {
    EXPECT_THAT(sizes, SizeIs(Gt(1)));
  }
}

TYPED_TEST(ContainerTest, SettingSizesLimitsOutput) {
  using T = TypeParam;

  TestMinMaxContainerSize(Arbitrary<T>().WithSize(7), 7, 7);
  TestMinMaxContainerSize(Arbitrary<T>().WithMinSize(7), 7, ~size_t{});
  TestMinMaxContainerSize(Arbitrary<T>().WithMaxSize(7), 0, 7);
  TestMinMaxContainerSize(Arbitrary<T>().WithMinSize(3).WithMaxSize(7), 3, 7);

  auto inner = Arbitrary<typename T::value_type>();

  TestMinMaxContainerSize(ContainerOf<T>(inner).WithSize(7), 7, 7);
  TestMinMaxContainerSize(ContainerOf<T>(inner).WithMinSize(7), 7, ~size_t{});
  TestMinMaxContainerSize(ContainerOf<T>(inner).WithMaxSize(7), 0, 7);
  TestMinMaxContainerSize(ContainerOf<T>(inner).WithMinSize(3).WithMaxSize(7),
                          3, 7);
  TestMinMaxContainerSize(NonEmpty(ContainerOf<T>(inner)), 1, ~size_t{});
}

TYPED_TEST(ContainerTest, GenearatesDifferentValuesWithFixedSize) {
  GenerateValues(Arbitrary<TypeParam>().WithSize(7));
}

TYPED_TEST(ContainerTest, InitGeneratesSeeds) {
  auto domain = Arbitrary<TypeParam>();
  absl::BitGen bitgen;
  auto seed = Value(domain, bitgen);
  seed.RandomizeByRepeatedMutation(domain, bitgen);
  domain.WithSeeds({seed.user_value});

  EXPECT_THAT(GenerateInitialValues(domain, 1000), Contains(seed));
}

TEST(StringTest, GetRandomValueYieldsSeedsAndOtherValues) {
  Domain<std::string> domain = Arbitrary<std::string>().WithSeeds({"seed"});

  absl::BitGen prng;
  bool seed_seen = false;
  bool other_seen = false;
  // To hit the seed, we need to first hit an initial value (p=1/1000) and
  // then hit the actual seed (p=1/2).
  static constexpr double kHitSeedProbability = 1.0 / 1000 * 1.0 / 2;
  for (int i = 0; !(seed_seen && other_seen) &&
                  i < IterationsToHitAll(/*num_cases=*/1, kHitSeedProbability);
       ++i) {
    auto val = domain.GetRandomValue(prng);
    if (val == "seed") {
      seed_seen = true;
    } else {
      other_seen = true;
    }
  }

  EXPECT_TRUE(seed_seen && other_seen);
}

TEST(Container, ValidationRejectsInvalidSize) {
  absl::BitGen bitgen;

  auto domain_a = Arbitrary<std::vector<int>>().WithSize(2);
  auto domain_b = Arbitrary<std::vector<int>>().WithSize(3);

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(domain_a.ValidateCorpusValue(value_b.corpus_value),
              IsInvalid("Invalid size: 3. Max size: 2"));
  EXPECT_THAT(domain_b.ValidateCorpusValue(value_a.corpus_value),
              IsInvalid("Invalid size: 2. Min size: 3"));
}

TEST(Container, ValidationRejectsInvalidElements) {
  absl::BitGen bitgen;

  auto domain_a = VectorOf(InRange(0, 9)).WithMinSize(1);
  auto domain_b = VectorOf(InRange(10, 12)).WithMinSize(1);

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(
      domain_a.ValidateCorpusValue(value_b.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value in container at index 0 >> The value .+ is not InRange\(0, 9\))")));
  EXPECT_THAT(
      domain_b.ValidateCorpusValue(value_a.corpus_value),
      IsInvalid(testing::MatchesRegex(
          R"(Invalid value in container at index 0 >> The value .+ is not InRange\(10, 12\))")));
}

// This should apply to all container types with memory dictionary mutation
// enabled, but we test on strings for simplification.
TEST(Container, MemoryDictionaryMutationMutatesEveryPossibleMatch) {
  auto domain = Arbitrary<std::string>();
  internal::TablesOfRecentCompares cmp_tables;
  cmp_tables.GetMutable<0>().Insert(reinterpret_cast<const uint8_t*>("abcd"),
                                    reinterpret_cast<const uint8_t*>("1234"),
                                    4);

  absl::BitGen bitgen;
  std::vector<std::string> mutants;
  for (int i = 0; i < 1000000; ++i) {
    std::string mutant = "abcdabcdabcdabcd";
    domain.Mutate(mutant, bitgen, {/*cmp_tables=*/&cmp_tables}, false);
    mutants.push_back(std::move(mutant));
  }

  EXPECT_THAT(mutants, testing::IsSupersetOf(std::vector<std::string>{
                           "1234abcdabcdabcd",
                           "abcd1234abcdabcd",
                           "abcdabcd1234abcd",
                           "abcdabcdabcd1234",
                       }));
}

TEST(Container, ValidatesMemoryDictionaryMutationForInnerDomain) {
  auto domain = VectorOf(InRange<uint8_t>(10, 128));
  internal::TablesOfRecentCompares cmp_tables;
  std::vector<std::vector<uint8_t>> cmp_entries = {{10, 11, 12, 13},
                                                   {129, 129, 129, 129},
                                                   {10, 11, 12, 13},
                                                   {17, 31, 113, 71}};
  // Fill the table with the same entries repeatly.
  for (int i = 0; i < cmp_tables.GetMutable<0>().kTableSize; ++i) {
    cmp_tables.GetMutable<0>().Insert(cmp_entries[0].data(),
                                      cmp_entries[1].data(), 4);
    cmp_tables.GetMutable<0>().Insert(cmp_entries[2].data(),
                                      cmp_entries[3].data(), 4);
  }

  absl::BitGen bitgen;
  std::vector<std::vector<uint8_t>> mutants;
  const double hit_probability =  //
      1.0 / 4                     // to use dictionaries
      * 1.0 / 4                   // to use cmp tables
      * 1.0 / 2                   // to pick the memcmp table
      * 1.0 / 2                   // to pick one of the entries
      * 1.0 / 2                   // to apply replacement
      ;
  for (int i = 0; i < 1 * IterationsToHitAll(/*num_cases=*/2, hit_probability);
       ++i) {
    std::vector<uint8_t> mutant = {10, 11, 12, 13};
    domain.Mutate(mutant, bitgen, {/*cmp_tables=*/&cmp_tables}, false);
    mutants.push_back(std::move(mutant));
  }

  EXPECT_THAT(mutants, Contains(std::vector<uint8_t>{17, 31, 113, 71}));
  EXPECT_THAT(mutants, Not(Contains(std::vector<uint8_t>{129, 129, 129, 129})));
}

}  // namespace
}  // namespace fuzztest
