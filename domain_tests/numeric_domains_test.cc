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

#include <bitset>
#include <cctype>
#include <cstdint>
#include <deque>
#include <iterator>
#include <limits>
#include <list>
#include <optional>
#include <set>
#include <string>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/substitute.h"
#include "./fuzztest/domain.h"
#include "./domain_tests/domain_testing.h"

namespace fuzztest {
namespace {

using ::testing::Ge;
using ::testing::Gt;
using ::testing::Le;
using ::testing::Lt;
using ::testing::Ne;

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
  const auto values = GenerateValues(domain);
  VerifyRoundTripThroughConversion(values, domain);
  TestShrink(
      domain, values,
      [](auto v) { return !std::isfinite(static_cast<double>(v)) || v == 0; },
      TowardsZero<T>);
}

TYPED_TEST(NumericTest, Positive) {
  using T = TypeParam;
  Domain<T> domain = Positive<T>();
  const auto values = GenerateValues(domain);
  for (auto v : values) ASSERT_THAT(v.user_value, Gt(0));
  TestShrink(
      domain, values, [](auto v) { return v <= 1; }, TowardsZero<T>);
}

TYPED_TEST(NumericTest, NonNegative) {
  using T = TypeParam;
  Domain<T> domain = NonNegative<T>();
  const auto values = GenerateValues(domain);
  for (auto v : values) ASSERT_THAT(v.user_value, Ge(0));
  TestShrink(
      domain, values, [](auto v) { return v == 0; }, TowardsZero<T>);
}

TYPED_TEST(SignedNumericTest, Negative) {
  using T = TypeParam;
  Domain<T> domain = Negative<T>();
  const auto values = GenerateValues(domain);
  for (auto v : values) ASSERT_THAT(v.user_value, Lt(0));
  TestShrink(
      domain, values, [](auto v) { return v >= -1; }, TowardsZero<T>);
}

TYPED_TEST(SignedNumericTest, NonPositive) {
  using T = TypeParam;
  Domain<T> domain = NonPositive<T>();
  const auto values = GenerateValues(domain);
  for (auto v : values) ASSERT_THAT(v.user_value, Le(0));
  TestShrink(
      domain, values, [](auto v) { return v == 0; }, TowardsZero<T>);
}

TYPED_TEST(NumericTest, InRange) {
  using T = TypeParam;
  T min = std::numeric_limits<T>::is_signed ? -100 : 10;
  T max = 120;
  T limit = std::numeric_limits<T>::is_signed ? T{0} : min;
  Domain<T> domain = InRange<T>(min, max);
  const auto values = GenerateValues(domain);
  VerifyRoundTripThroughConversion(values, domain);
  for (auto v : values) ASSERT_THAT(v.user_value, IsInClosedRange(min, max));
  TestShrink(
      domain, values, [=](auto v) { return v == limit; },
      [=](auto prev, auto next) {
        // Next is within prev and limit.
        return (limit <= next && next < prev) || (prev < next && next <= limit);
      });

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
  const auto values = GenerateValues(domain);
  for (auto v : values) ASSERT_THAT(v.user_value, Ne(0));
}

TEST(Finite, CreatesFiniteFloatingPointValuesAndShrinksTowardsZero) {
  Domain<double> domain = Finite<double>();
  const auto values = GenerateValues(domain);
  for (auto v : values) ASSERT_TRUE(std::isfinite(v.user_value));
  TestShrink(
      domain, values, [](auto v) { return std::abs(v) <= 1; },
      TowardsZero<double>);
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
