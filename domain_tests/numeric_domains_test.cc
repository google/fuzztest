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
#include "absl/types/span.h"
#include "./fuzztest/domain.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/serialization.h"

namespace fuzztest {
namespace {

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
TYPED_TEST_SUITE(NumericTest, NumericTypes);

template <typename T>
class SignedNumericTest : public testing::Test {};
using SignedNumericTypes = testing::Types<signed char,       //
                                          short, int, long,  // NOLINT
                                          long long,         // NOLINT
                                          float, double>;    //
TYPED_TEST_SUITE(SignedNumericTest, SignedNumericTypes);

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

TYPED_TEST(NumericTest, InRangeDeserializesCorrectly) {
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

  EXPECT_TRUE(
      domain
          .ParseCorpus(*internal::IRObject::FromString(absl::StrCat(
              "FUZZTESTv1 ",
              absl::Substitute(serialized_format, static_cast<int32_t>(max)))))
          .has_value());
  // Greater than max should not be true
  EXPECT_FALSE(
      domain
          .ParseCorpus(*internal::IRObject::FromString(absl::StrCat(
              "FUZZTESTv1 ", absl::Substitute(serialized_format,
                                              static_cast<int32_t>(max) + 1))))
          .has_value());
}

TYPED_TEST(NumericTest, NonZero) {
  using T = TypeParam;
  Domain<T> domain = NonZero<T>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/10, /*num_mutations=*/100);
  ASSERT_THAT(values, SizeIs(Ge(110)));
  for (auto v : values) ASSERT_THAT(v.user_value, Ne(0));
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

TEST(InRange, FailsWithInfiniteRange) {
  EXPECT_DEATH_IF_SUPPORTED(InRange(std::numeric_limits<double>::lowest(),
                                    std::numeric_limits<double>::max()),
                            "Failed precondition.*Finite");
}

TEST(InRange, FailsWithInvalidRange) {
  EXPECT_DEATH_IF_SUPPORTED(InRange(10, 1),
                            "Failed precondition.*min must be smaller");
}

TEST(IllegalInputs, Numeric) {
  absl::BitGen bitgen;
  const std::vector<int> values{-10, -1, 0, 1};
  auto restricted_domain = Positive<int>();
  for (int value : values) {
    restricted_domain.Mutate(value, bitgen, false);
    ASSERT_GT(value, 0);
  }
  for (int value : values) {
    restricted_domain.Mutate(value, bitgen, true);
    ASSERT_GT(value, 0);
  }
}

}  // namespace
}  // namespace fuzztest
