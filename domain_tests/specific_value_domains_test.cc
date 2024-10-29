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

// Tests of ElementOf and Just, which are domains that yield values from an
// explicitly specified set of values.

#include <optional>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/random.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzztest/domain_core.h"
#include "./domain_tests/domain_testing.h"

namespace fuzztest {
namespace {

using ::testing::Contains;
using ::testing::Eq;
using ::testing::Ge;
using ::testing::Ne;
using ::testing::SizeIs;
using ::testing::UnorderedElementsAreArray;

TEST(ElementOfTest, TwoOptions) {
  absl::BitGen bitgen;
  Domain<int> domain = ElementOf({0, 1});

  absl::flat_hash_set<Value<Domain<int>>> found;

  for (int i = 0; i < 20; ++i) {
    found.insert(Value(domain, bitgen));
  }
  ASSERT_THAT(found, SizeIs(2));

  for (const auto& v : found) {
    auto copy = v;
    copy.Mutate(domain, bitgen, {}, false);
    EXPECT_NE(v, copy);
  }
}

TEST(ElementOfTest, InitGeneratesSeeds) {
  Domain<int> domain = ElementOf({0, 1}).WithSeeds(std::vector{0});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, 0))
                  // Since there are only two possible values, the seed will
                  // surely appear at least once. To make the test meaningful,
                  // we expect to see it much more often than the other value.
                  .Times(Ge(650)));
}

TEST(ElementOfTest, InvalidInputReportsErrors) {
  EXPECT_DEATH_IF_SUPPORTED(ElementOf<int>({}),
                            "ElementOf requires a non empty list.");
}

enum class Color : int { Red, Green, Blue, Yellow };

TEST(ElementOfTest, Colors) {
  absl::BitGen bitgen;
  std::vector<Color> all_colors{Color::Red, Color::Green, Color::Blue,
                                Color::Yellow};
  auto domain = ElementOf(all_colors);
  absl::flat_hash_set<Color> found;
  while (found.size() < all_colors.size()) {
    found.insert(Value(domain, bitgen).user_value);
  }
  ASSERT_THAT(found, UnorderedElementsAreArray(all_colors));

  found.clear();
  Value c(domain, bitgen);
  while (found.size() < all_colors.size()) {
    c.Mutate(domain, bitgen, {}, false);
    found.insert(c.user_value);

    VerifyRoundTripThroughConversion(c, domain);
  }
  ASSERT_THAT(found, UnorderedElementsAreArray(all_colors));

  c = Value(domain, bitgen);
  while (c.user_value != Color::Red) {
    auto prev = c.user_value;
    c.Mutate(domain, bitgen, {}, true);
    ASSERT_LE(c.user_value, prev);
  }
  ASSERT_THAT(found, UnorderedElementsAreArray(all_colors));
}

TEST(ElementOfTest, ValidationRejectsInvalidValue) {
  auto domain_a = ElementOf({'a', 'b'});
  auto domain_b = ElementOf({'a', 'b', 'c'});

  auto corpus_value_a = domain_a.FromValue('a');
  auto corpus_value_b = domain_b.FromValue('c');

  ASSERT_OK(domain_a.ValidateCorpusValue(*corpus_value_a));
  ASSERT_OK(domain_b.ValidateCorpusValue(*corpus_value_b));

  EXPECT_THAT(domain_a.ValidateCorpusValue(*corpus_value_b),
              IsInvalid("Invalid ElementOf() value"));
}

TEST(ElementOfTest, FromValueSupportsAbslDuration) {
  Domain<absl::Duration> domain =
      ElementOf({absl::ZeroDuration(), absl::Seconds(1)});

  EXPECT_THAT(domain.FromValue(absl::ZeroDuration()), Ne(std::nullopt));
  EXPECT_THAT(domain.FromValue(absl::Seconds(1)), Ne(std::nullopt));
  EXPECT_THAT(domain.FromValue(absl::Seconds(2)), Eq(std::nullopt));
}

TEST(ElementOfTest, FromValueSupportsAbslTime) {
  Domain<absl::Time> domain =
      ElementOf({absl::UnixEpoch(), absl::InfiniteFuture()});

  EXPECT_THAT(domain.FromValue(absl::UnixEpoch()), Ne(std::nullopt));
  EXPECT_THAT(domain.FromValue(absl::InfiniteFuture()), Ne(std::nullopt));
  EXPECT_THAT(domain.FromValue(absl::InfinitePast()), Eq(std::nullopt));
}

TEST(Just, Basic) {
  absl::BitGen bitgen;
  auto domain = Just(3);

  for (int i = 0; i < 10; ++i) {
    Value v(domain, bitgen);
    EXPECT_EQ(v.user_value, 3);
  }
  int n = 3;
  for (int i = 0; i < 10; ++i) {
    Value v(domain, bitgen);
    v.Mutate(domain, bitgen, {}, false);

    VerifyRoundTripThroughConversion(v, domain);
    EXPECT_EQ(n, 3);
  }
}

}  // namespace
}  // namespace fuzztest
