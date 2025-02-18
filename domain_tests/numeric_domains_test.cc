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

// Tests of domains in involving numbers, mostly Arbitrary<T> for some numeric
// type, but also Positive, Negative, NonZero, NonPositive, NonNegative, and
// InRange.

#include <cmath>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <type_traits>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/numeric/int128.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/substitute.h"
#include "./fuzztest/domain_core.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/serialization.h"

namespace fuzztest {
namespace {

using ::fuzztest::internal::IRObject;
using ::testing::AllOf;
using ::testing::Contains;
using ::testing::Each;
using ::testing::Field;
using ::testing::Ge;
using ::testing::Gt;
using ::testing::Le;
using ::testing::Lt;
using ::testing::Ne;
using ::testing::SizeIs;

template <typename T>
class NumericTest : public testing::Test {};
using NumericTypes = testing::Types<char, signed char, unsigned char,  //
                                    short, unsigned short,             // NOLINT
                                    int, unsigned int,                 //
                                    long, unsigned long,               // NOLINT
                                    long long, unsigned long long,     // NOLINT
                                    float, double,                     //
                                    absl::int128, absl::uint128>;
TYPED_TEST_SUITE(NumericTest, NumericTypes, );

template <typename T>
class SignedNumericTest : public testing::Test {};
using SignedNumericTypes = testing::Types<signed char,       //
                                          short, int, long,  // NOLINT
                                          long long,         // NOLINT
                                          float, double>;    //
TYPED_TEST_SUITE(SignedNumericTest, SignedNumericTypes, );

TYPED_TEST(NumericTest, Arbitrary) {
  using T = TypeParam;
  Domain<T> domain = Arbitrary<T>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/10, /*num_mutations=*/100);
  ASSERT_THAT(values, SizeIs(Ge(110)));
  VerifyRoundTripThroughConversion(values, domain);
  ASSERT_TRUE(TestShrink(
                  domain, values,
                  [](auto v) {
                    return !std::isfinite(static_cast<double>(v)) || v == 0;
                  },
                  TowardsZero<T>)
                  .ok());
}

TYPED_TEST(NumericTest, InitGeneratesSeeds) {
  using T = TypeParam;
  auto domain = Arbitrary<T>().WithSeeds({T{7}, T{42}});

  EXPECT_THAT(
      GenerateInitialValues(domain, 1000),
      AllOf(Contains(Value(domain, T{7})), Contains(Value(domain, T{42}))));
}

TYPED_TEST(NumericTest, Positive) {
  using T = TypeParam;
  Domain<T> domain = Positive<T>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/10, /*num_mutations=*/100);
  ASSERT_THAT(values, SizeIs(Ge(110)));
  for (auto v : values) ASSERT_THAT(v.user_value, Gt(0));
  ASSERT_TRUE(TestShrink(
                  domain, values, [](auto v) { return v <= 1; }, TowardsZero<T>)
                  .ok());
}

TYPED_TEST(NumericTest, NonNegative) {
  using T = TypeParam;
  Domain<T> domain = NonNegative<T>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/10, /*num_mutations=*/100);
  ASSERT_THAT(values, SizeIs(Ge(110)));
  for (auto v : values) ASSERT_THAT(v.user_value, Ge(0));
  ASSERT_TRUE(TestShrink(
                  domain, values, [](auto v) { return v == 0; }, TowardsZero<T>)
                  .ok());
}

TYPED_TEST(SignedNumericTest, Negative) {
  using T = TypeParam;
  Domain<T> domain = Negative<T>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/10, /*num_mutations=*/100);
  ASSERT_THAT(values, SizeIs(Ge(110)));
  for (auto v : values) ASSERT_THAT(v.user_value, Lt(0));
  ASSERT_TRUE(
      TestShrink(
          domain, values, [](auto v) { return v >= -1; }, TowardsZero<T>)
          .ok());
}

TYPED_TEST(SignedNumericTest, NonPositive) {
  using T = TypeParam;
  Domain<T> domain = NonPositive<T>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/10, /*num_mutations=*/100);
  ASSERT_THAT(values, SizeIs(Ge(110)));
  for (auto v : values) ASSERT_THAT(v.user_value, Le(0));
  ASSERT_TRUE(TestShrink(
                  domain, values, [](auto v) { return v == 0; }, TowardsZero<T>)
                  .ok());
}

TYPED_TEST(NumericTest, InRangeVerifiesRoundTripThroughConversion) {
  using T = TypeParam;
  const T min = std::numeric_limits<T>::is_signed ? -100 : 10;
  const T max = 120;
  Domain<T> domain = InRange<T>(min, max);
  const absl::flat_hash_set<Value<Domain<T>>> values =
      GenerateValues(domain,
                     /*num_seeds=*/10, /*num_mutations=*/100);
  ASSERT_THAT(values, SizeIs(Ge(110)));
  VerifyRoundTripThroughConversion(values, domain);
}

TYPED_TEST(NumericTest, InRangeProducesValuesInClosedRange) {
  using T = TypeParam;
  const T min = std::numeric_limits<T>::is_signed ? -100 : 10;
  const T max = 120;
  Domain<T> domain = InRange<T>(min, max);
  const absl::flat_hash_set<Value<Domain<T>>> values =
      GenerateValues(domain,
                     /*num_seeds=*/10, /*num_mutations=*/100);
  ASSERT_THAT(values, SizeIs(Ge(110)));
  ASSERT_THAT(values, Each(Field(&Value<Domain<T>>::user_value,
                                 IsInClosedRange(min, max))));
}

TYPED_TEST(NumericTest, ShrinkingWorksForInRange) {
  using T = TypeParam;
  const T min = std::numeric_limits<T>::is_signed ? -100 : 10;
  const T max = 120;
  const T limit = std::numeric_limits<T>::is_signed ? T{0} : min;
  Domain<T> domain = InRange<T>(min, max);
  const absl::flat_hash_set<Value<Domain<T>>> values =
      GenerateValues(domain,
                     /*num_seeds=*/10, /*num_mutations=*/100);
  ASSERT_THAT(values, SizeIs(Ge(110)));

  ASSERT_TRUE(TestShrink(
                  domain, values, [=](auto v) { return v == limit; },
                  [=](auto prev, auto next) {
                    // Next is within prev and limit.
                    return (limit <= next && next < prev) ||
                           (prev < next && next <= limit);
                  })
                  .ok());
}

TYPED_TEST(NumericTest, InRangeValidationRejectsInvalidRange) {
  using T = TypeParam;

  absl::BitGen bitgen;

  const T min_a = std::numeric_limits<T>::is_signed ? -100 : 10;
  const T max_a = 42;
  const T min_b = 48;
  const T max_b = std::numeric_limits<T>::max();

  Domain<T> domain_a = InRange<T>(min_a, max_a);
  Domain<T> domain_b = InRange<T>(min_b, max_b);

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(
      domain_a.ValidateCorpusValue(value_b.corpus_value),
      IsInvalid(testing::MatchesRegex(R"(The value .+ is not InRange\(.+\))")));
  EXPECT_THAT(
      domain_b.ValidateCorpusValue(value_a.corpus_value),
      IsInvalid(testing::MatchesRegex(R"(The value .+ is not InRange\(.+\))")));
}

TYPED_TEST(NumericTest, InRangeGeneratesSpecialValues) {
  using T = TypeParam;
  auto domain = InRange<T>(T{0}, T{127});

  absl::flat_hash_set<T> values;
  absl::BitGen prng;
  for (int i = 0;
       !(values.contains(T{0}) && values.contains(T{1})) &&
       i < IterationsToHitAll(/*num_cases=*/2, /*hit_probability=*/1.0 / 4);
       ++i) {
    values.insert(domain.GetRandomValue(prng));
  }

  EXPECT_THAT(values, AllOf(Contains(T{0}), Contains(T{1})));
}

TYPED_TEST(NumericTest, InRangeValueIsParsedCorrectly) {
  using T = TypeParam;
  const T min = std::numeric_limits<T>::is_signed ? -100 : 10;
  const T max = 120;
  Domain<T> domain = InRange<T>(min, max);

  static constexpr bool is_at_most_64_bit_integer =
      std::numeric_limits<T>::is_integer && sizeof(T) <= sizeof(uint64_t);
  const std::string serialized_format =
      std::is_floating_point<T>::value ? "d: $0"
      : is_at_most_64_bit_integer      ? "i: $0"
                                       : R"(sub { i: 0 } sub { i: $0 })";

  auto corpus_value = domain.ParseCorpus(*IRObject::FromString(absl::StrCat(
      "FUZZTESTv1 ",
      absl::Substitute(serialized_format, static_cast<int32_t>(max)))));
  ASSERT_TRUE(corpus_value.has_value());
  EXPECT_OK(domain.ValidateCorpusValue(*corpus_value));

  corpus_value = domain.ParseCorpus(*IRObject::FromString(absl::StrCat(
      "FUZZTESTv1 ",
      absl::Substitute(serialized_format, static_cast<int32_t>(max) + 1))));
  // Greater than max should be parsed, but rejected by validation.
  ASSERT_TRUE(corpus_value.has_value());
  EXPECT_THAT(
      domain.ValidateCorpusValue(*corpus_value),
      IsInvalid(testing::MatchesRegex(R"(The value .+ is not InRange\(.+\))")));
}

TYPED_TEST(NumericTest, NonZero) {
  using T = TypeParam;
  Domain<T> domain = NonZero<T>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/10, /*num_mutations=*/100);
  ASSERT_THAT(values, SizeIs(Ge(110)));
  for (auto v : values) ASSERT_THAT(v.user_value, Ne(0));
}

template <typename T>
class CharTest : public testing::Test {};
using CharTypes = testing::Types<char, signed char, unsigned char>;

TYPED_TEST_SUITE(CharTest, CharTypes, );

TYPED_TEST(CharTest, GetRandomValueYieldsEveryValue) {
  using T = TypeParam;
  Domain<T> domain = Arbitrary<T>();

  absl::flat_hash_set<T> values;
  absl::BitGen prng;
  for (int i = 0;
       values.size() < 256 &&
       i < IterationsToHitAll(/*num_cases=*/256, /*hit_probability=*/1.0 / 256);
       ++i) {
    values.insert(domain.GetRandomValue(prng));
  }

  EXPECT_THAT(values, SizeIs(256));
}

TEST(Finite, CreatesFiniteFloatingPointValuesAndShrinksTowardsZero) {
  Domain<double> domain = Finite<double>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/10, /*num_mutations=*/100);
  ASSERT_THAT(values, SizeIs(Ge(110)));
  for (auto v : values) ASSERT_TRUE(std::isfinite(v.user_value));
  ASSERT_TRUE(TestShrink(
                  domain, values, [](auto v) { return std::abs(v) <= 1; },
                  TowardsZero<double>)
                  .ok());
}

TEST(InRange, InitGeneratesSeeds) {
  auto domain =
      InRange(std::numeric_limits<int>::min(), std::numeric_limits<int>::max())
          .WithSeeds({7, 42});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              AllOf(Contains(Value(domain, 7)), Contains(Value(domain, 42))));
}

TEST(InRange, InitGeneratesSeedsFromSeedProvider) {
  auto domain =
      InRange(std::numeric_limits<int>::min(), std::numeric_limits<int>::max())
          .WithSeeds([]() -> std::vector<int> { return {7, 42}; });

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              AllOf(Contains(Value(domain, 7)), Contains(Value(domain, 42))));
}

TEST(InRange, WithSeedsFailsWhenSeedValidationFails) {
  EXPECT_DEATH_IF_SUPPORTED(InRange(0, 40).WithSeeds({42}),
                            "Invalid seed value");
}

TEST(InRange, InitFailsWhenValidatingSeedsFromSeedProviderFails) {
  auto domain =
      InRange(0, 40).WithSeeds([]() -> std::vector<int> { return {42}; });

  EXPECT_DEATH_IF_SUPPORTED(GenerateInitialValues(domain, 1000),
                            "Invalid seed value");
}

TEST(InRange, FailsWithInfiniteRange) {
  EXPECT_DEATH_IF_SUPPORTED(InRange(std::numeric_limits<double>::lowest(),
                                    std::numeric_limits<double>::max()),
                            "Failed precondition.*Finite");
}

TEST(InRange, FailsWithInvalidRange) {
  EXPECT_DEATH_IF_SUPPORTED(
      InRange(10, 1),
      "Failed precondition.*min must be less than or equal to max");
}

TEST(InRange, SupportsSingletonRange) {
  auto domain = InRange(10, 10);
  absl::BitGen bitgen;
  auto val = Value(domain, bitgen);
  val.Mutate(domain, bitgen, {}, false);

  EXPECT_EQ(val.user_value, 10);
}

TEST(InRange, GetRandomValueYieldsEveryValue) {
  auto domain = InRange(1, 64);

  absl::flat_hash_set<int> values;
  absl::BitGen prng;
  // InRange is biased towards extreme values. Conservatively, we use the
  // probability to hit a non-extreme value for all values.
  static constexpr double kHitProbability = 1.0 / 3 * 1.0 / 64;
  for (int i = 0; values.size() < 64 &&
                  i < IterationsToHitAll(/*num_cases=*/64, kHitProbability);
       ++i) {
    values.insert(domain.GetRandomValue(prng));
  }

  EXPECT_THAT(values, SizeIs(64));
}

TEST(IllegalInputs, Numeric) {
  absl::BitGen bitgen;
  const std::vector<int> values{-10, -1, 0, 1};
  auto restricted_domain = Positive<int>();
  for (int value : values) {
    restricted_domain.Mutate(value, bitgen, {}, false);
    ASSERT_GT(value, 0);
  }
  for (int value : values) {
    restricted_domain.Mutate(value, bitgen, {}, true);
    ASSERT_GT(value, 0);
  }
}

}  // namespace
}  // namespace fuzztest
