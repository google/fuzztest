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

// Tests of Arbitrary<T> domains.

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/strings/cord.h"
#include "absl/time/time.h"
#include "./fuzztest/domain_core.h"  // IWYU pragma: keep
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/test_protobuf.pb.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest {
namespace {

using ::fuzztest::domain_implementor::DomainBase;
using ::fuzztest::domain_implementor::MutationMetadata;
using ::fuzztest::internal::IRObject;
using ::testing::Contains;
using ::testing::Each;
using ::testing::Ge;
using ::testing::IsEmpty;
using ::testing::SizeIs;
using ::testing::UnorderedElementsAre;

TEST(BoolTest, Arbitrary) {
  absl::BitGen bitgen;
  Domain<bool> domain = Arbitrary<bool>();
  bool found[2]{};
  for (int i = 0; i < 20; ++i) {
    found[Value(domain, bitgen).user_value] = true;
  }
  ASSERT_THAT(found, Each(true));

  Value b(domain, bitgen);
  bool copy = b.user_value;
  b.Mutate(domain, bitgen, {}, false);
  EXPECT_NE(b.user_value, copy);
  b.Mutate(domain, bitgen, {}, false);
  EXPECT_EQ(b.user_value, copy);
}

TEST(ArbitraryBoolTest, InitGeneratesSeeds) {
  Domain<bool> domain = Arbitrary<bool>().WithSeeds({true});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, true))
                  // Since there are only two possible values, the seed will
                  // surely appear at least once. To make the test meaningful,
                  // we expect to see it much more often than the other value.
                  .Times(Ge(650)));
}

TEST(ArbitraryByteTest, RepeatedMutationYieldsEveryValue) {
  Domain<std::byte> domain = Arbitrary<std::byte>();
  // Verify every value appears.
  auto values = MutateUntilFoundN(domain, 256);
  VerifyRoundTripThroughConversion(values, domain);
  EXPECT_EQ(values.size(), 256);
}

TEST(ArbitraryByteTest, InitGeneratesSeeds) {
  auto domain = Arbitrary<std::byte>().WithSeeds({std::byte{42}});

  // With a 1000 tries, it's likely that any specific value will show up. To
  // make this test meaningful, we expect to see the seed many more times than
  // in a uniform distribution.
  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, std::byte{42})).Times(Ge(350)));
}

TEST(ArbitraryByteTest, GetRandomValueYieldsEveryValue) {
  Domain<std::byte> domain = Arbitrary<std::byte>();

  absl::flat_hash_set<std::byte> values;
  absl::BitGen prng;
  for (int i = 0;
       values.size() < 256 &&
       i < IterationsToHitAll(/*num_cases=*/256, /*hit_probability=*/1.0 / 256);
       ++i) {
    values.insert(domain.GetRandomValue(prng));
  }

  EXPECT_THAT(values, SizeIs(256));
}

struct MyStruct {
  int a;
  std::string s;

  // These are for the tests below that try to get N distinct values.
  friend bool operator==(const MyStruct& lhs, const MyStruct& rhs) {
    return std::tie(lhs.a, lhs.s) == std::tie(rhs.a, rhs.s);
  }
  [[maybe_unused]] friend bool operator!=(const MyStruct& lhs,
                                          const MyStruct& rhs) {
    return !(lhs == rhs);
  }
  template <typename H>
  friend H AbslHashValue(H state, const MyStruct& v) {
    return H::combine(std::move(state), v.a, v.s);
  }
};

template <typename T>
class CompoundTypeTest : public testing::Test {};

// TODO(sbenzaquen): Consider supporting Abseil types directly on Arbitrary<>.
using CompoundTypeTypes =
    testing::Types<std::pair<int, std::string>, std::tuple<int>,
                   std::tuple<bool, int, std::string>, std::array<int, 1>,
                   std::array<int, 100>, std::variant<int, bool>,
                   std::optional<int>, std::unique_ptr<std::string>, MyStruct,
                   std::vector<bool>>;

TYPED_TEST_SUITE(CompoundTypeTest, CompoundTypeTypes, );

TYPED_TEST(CompoundTypeTest, Arbitrary) {
  Domain<TypeParam> domain = Arbitrary<TypeParam>();
  auto values = MutateUntilFoundN(domain, 100);
  VerifyRoundTripThroughConversion(values, domain);
  // Just make sure we can find 100 different objects.
  // No need to look into their actual values.
  EXPECT_EQ(values.size(), 100);
}

TYPED_TEST(CompoundTypeTest, InitGeneratesSeeds) {
  // Seed cannot be a move-only type like std::unique_ptr<std::string>.
  if constexpr (std::is_copy_constructible_v<TypeParam>) {
    auto domain = Arbitrary<TypeParam>();
    absl::BitGen bitgen;
    auto seed = Value(domain, bitgen);
    seed.RandomizeByRepeatedMutation(domain, bitgen);
    domain.WithSeeds({seed.user_value});

    EXPECT_THAT(GenerateInitialValues(domain, 1000), Contains(seed));
  }
}

template <typename T>
class MonostateTypeTest : public testing::Test {};

using MonostateTypeTypes = testing::Types<std::true_type, std::false_type,
                                          std::array<int, 0>, std::tuple<>>;

TYPED_TEST_SUITE(MonostateTypeTest, MonostateTypeTypes, );

TYPED_TEST(MonostateTypeTest, Arbitrary) {
  absl::BitGen bitgen;
  // Minimal check that Arbitrary<T> works for monostate types.
  Domain<TypeParam> domain = Arbitrary<TypeParam>();
  // Init returns a value.
  auto v = domain.Init(bitgen);
  // Mutate "works". That is, it returns.
  // We don't expect it to do anything else since the value can't be changed.
  domain.Mutate(v, bitgen, {}, false);
}

struct BinaryTree {
  int i;
  std::unique_ptr<BinaryTree> lhs;
  std::unique_ptr<BinaryTree> rhs;

  int count_nodes() const {
    return 1 + (lhs ? lhs->count_nodes() : 0) + (rhs ? rhs->count_nodes() : 0);
  }
};

TEST(UserDefinedAggregate, NestedArbitrary) {
  auto domain = Arbitrary<BinaryTree>();
  absl::BitGen bitgen;

  Value v(domain, bitgen);
  Set<int> s;
  while (s.size() < 10) {
    s.insert(v.user_value.count_nodes());
    v.Mutate(domain, bitgen, {}, false);
  }
}

struct StatefulIncrementDomain
    : public DomainBase<StatefulIncrementDomain, int,
                        // Just to make sure we don't mix value_type with
                        // corpus_type
                        std::tuple<int>> {
  corpus_type Init(absl::BitGenRef prng) {
    // Minimal code to exercise prng.
    corpus_type result = {absl::Uniform<value_type>(prng, i, i + 1)};
    ++i;
    return result;
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng,
              const MutationMetadata& metadata, bool only_shrink) {
    std::get<0>(val) += absl::Uniform<value_type>(prng, 5, 6) +
                        static_cast<value_type>(only_shrink);
  }

  value_type GetValue(corpus_type v) const { return std::get<0>(v); }
  std::optional<corpus_type> FromValue(value_type v) const {
    return std::tuple{v};
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    return obj.ToCorpus<corpus_type>();
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return IRObject::FromCorpus(v);
  }

  absl::Status ValidateCorpusValue(const corpus_type&) const {
    return absl::OkStatus();
  }

  auto GetPrinter() const { return internal::IntegralPrinter{}; }

  value_type i = 0;
};

TEST(Domain, Constructability) {
  EXPECT_TRUE(
      (std::is_constructible_v<Domain<int>, internal::ArbitraryImpl<int>>));
  // Wrong type
  EXPECT_FALSE(
      (std::is_constructible_v<Domain<int>, internal::ArbitraryImpl<char>>));
  struct NoBase {};
  EXPECT_FALSE((std::is_constructible_v<Domain<int>, NoBase>));
}

TEST(Domain, BasicVerify) {
  Domain<int> domain = StatefulIncrementDomain{};

  absl::BitGen bitgen;

  EXPECT_EQ(Value(domain, bitgen), 0);
  EXPECT_EQ(Value(domain, bitgen), 1);

  Domain<int> copy = domain;
  EXPECT_EQ(Value(domain, bitgen), 2);
  EXPECT_EQ(Value(domain, bitgen), 3);
  // `copy` has its own state.
  EXPECT_EQ(Value(copy, bitgen), 2);
  domain = copy;
  EXPECT_EQ(Value(domain, bitgen), 3);
  EXPECT_EQ(Value(copy, bitgen), 3);

  Value i(domain, bitgen);
  Value j = i;
  i.Mutate(domain, bitgen, {}, false);
  EXPECT_THAT(i.user_value, j.user_value + 5);
  i.Mutate(domain, bitgen, {}, true);
  EXPECT_THAT(i.user_value, j.user_value + 11);
}

TEST(SequenceContainerMutation, CopyPartRejects) {
  std::string to_initial = "abcd";
  std::string to;
  std::string from = "efgh";

  // Rejects zero size of from.
  to = to_initial;
  EXPECT_FALSE(internal::CopyPart<false>(from, to, 0, 0, 4, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects invalid starting offset of from.
  to = to_initial;
  EXPECT_FALSE(internal::CopyPart<false>(from, to, 4, 1, 4, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects invalid starting offset of to.
  to = to_initial;
  EXPECT_FALSE(internal::CopyPart<false>(from, to, 3, 1, 5, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects invalid size of from.
  to = to_initial;
  EXPECT_FALSE(internal::CopyPart<false>(from, to, 0, 5, 4, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects larger than max copy.
  to = to_initial;
  EXPECT_FALSE(internal::CopyPart<false>(from, to, 0, 4, 4, 7));
  EXPECT_EQ(to, to_initial);
  // Rejects no mutation.
  to = to_initial;
  EXPECT_FALSE(internal::CopyPart<false>(to_initial, to, 0, 3, 0, 10));
  EXPECT_EQ(to, to_initial);
}

TEST(SequenceContainerMutation, CopyPartAccepts) {
  std::string to_initial = "abcd";
  std::string to;
  std::string from = "efgh";

  // Accepts and mutates.
  to = to_initial;
  EXPECT_TRUE(internal::CopyPart<false>(from, to, 0, 3, 0, 10));
  EXPECT_EQ(to, "efgd");
  to = to_initial;
  EXPECT_TRUE(internal::CopyPart<false>(from, to, 0, 4, 4, 10));
  EXPECT_EQ(to, "abcdefgh");
  to = to_initial;
  EXPECT_TRUE(internal::CopyPart<false>(from, to, 0, 4, 2, 10));
  EXPECT_EQ(to, "abefgh");

  // Accepts self-copy.
  to = to_initial;
  EXPECT_TRUE(internal::CopyPart<true>(to, to, 0, 3, 1, 10));
  EXPECT_EQ(to, "aabc");
}

TEST(SequenceContainerMutation, InsertPartRejects) {
  std::string to_initial = "abcd";
  std::string to;
  std::string from = "efgh";
  // Rejects zero size of from.
  to = to_initial;
  EXPECT_FALSE(internal::InsertPart<false>(from, to, 0, 0, 4, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects invalid starting offset of from.
  to = to_initial;
  EXPECT_FALSE(internal::InsertPart<false>(from, to, 4, 1, 4, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects invalid starting offset of to.
  to = to_initial;
  EXPECT_FALSE(internal::InsertPart<false>(from, to, 3, 1, 5, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects invalid size of from.
  to = to_initial;
  EXPECT_FALSE(internal::InsertPart<false>(from, to, 0, 5, 4, 10));
  EXPECT_EQ(to, to_initial);
  // Rejects larger than max insertion.
  to = to_initial;
  EXPECT_FALSE(internal::InsertPart<false>(from, to, 0, 4, 4, 7));
  EXPECT_EQ(to, to_initial);
}

TEST(SequenceContainerMutation, InsertPartAccepts) {
  std::string to_initial = "abcd";
  std::string to;
  std::string from = "efgh";

  // Accepts and mutates.
  to = to_initial;
  EXPECT_TRUE(internal::InsertPart<false>(from, to, 0, 4, 0, 10));
  EXPECT_EQ(to, "efghabcd");
  to = to_initial;
  EXPECT_TRUE(internal::InsertPart<false>(from, to, 0, 4, 4, 10));
  EXPECT_EQ(to, "abcdefgh");
  to = to_initial;
  EXPECT_TRUE(internal::InsertPart<false>(from, to, 0, 4, 2, 10));
  EXPECT_EQ(to, "abefghcd");

  // Accepts self-copy.
  to = to_initial;
  EXPECT_TRUE(internal::InsertPart<true>(to, to, 0, 3, 1, 10));
  EXPECT_EQ(to, "aabcbcd");
}

// Note: this test is based on knowledge of internal representation of
// absl::Duration and will fail if the internal representation changes.
TEST(ArbitraryDurationTest, ValidatesAssumptionsAboutAbslDurationInternals) {
  absl::Duration min_positive = absl::Nanoseconds(1) / 4;
  absl::Duration max = absl::Seconds(std::numeric_limits<int64_t>::max()) +
                       (absl::Seconds(1) - min_positive);

  EXPECT_NE(absl::ZeroDuration(), min_positive);
  EXPECT_EQ(absl::ZeroDuration(), (min_positive / 2));
  EXPECT_NE(absl::InfiniteDuration(), max);
  EXPECT_EQ(absl::InfiniteDuration(), max + min_positive);
}

TEST(ArbitraryDurationTest, ValidatesMakeDurationResults) {
  EXPECT_EQ(internal::MakeDuration(0, 0), absl::ZeroDuration());
  EXPECT_EQ(internal::MakeDuration(0, 1), absl::Nanoseconds(0.25));
  EXPECT_EQ(internal::MakeDuration(0, 400'000), absl::Microseconds(100));
  EXPECT_EQ(internal::MakeDuration(1, 500'000'000), absl::Seconds(1.125));
  EXPECT_EQ(internal::MakeDuration(-50, 30), absl::Seconds(-49.9999999925));
  EXPECT_EQ(internal::MakeDuration(-1, 3'999'999'999u),
            absl::Nanoseconds(-0.25));
  EXPECT_EQ(internal::MakeDuration(-2, 3'999'999'999u),
            absl::Seconds(-1.00000000025));
}

TEST(ArbitraryDurationTest, ValidatesGetSecondsResults) {
  EXPECT_EQ(internal::GetSeconds(internal::MakeDuration(10, 20)), 10);
  EXPECT_EQ(internal::GetSeconds(internal::MakeDuration(-50, 30)), -50);
  EXPECT_EQ(internal::GetSeconds(internal::MakeDuration(
                std::numeric_limits<int64_t>::min(), 10)),
            std::numeric_limits<int64_t>::min());
  EXPECT_EQ(internal::GetSeconds(internal::MakeDuration(
                std::numeric_limits<int64_t>::max(), 10)),
            std::numeric_limits<int64_t>::max());
}

TEST(ArbitraryDurationTest, ValidatesGetTicksResults) {
  EXPECT_EQ(internal::GetTicks(internal::MakeDuration(100, 200)), 200);
  EXPECT_EQ(internal::GetTicks(internal::MakeDuration(-100, 200)), 200);
  EXPECT_EQ(internal::GetTicks(internal::MakeDuration(
                std::numeric_limits<int64_t>::min(), 3'999'999'999u)),
            3'999'999'999u);
  EXPECT_EQ(internal::GetTicks(internal::MakeDuration(
                std::numeric_limits<int64_t>::max(), 3'999'999'999u)),
            3'999'999'999u);
}

TEST(ArbitraryDurationTest, InitGeneratesSeeds) {
  Domain<absl::Duration> domain =
      Arbitrary<absl::Duration>().WithSeeds({absl::Seconds(42)});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, absl::Seconds(42))));
}

enum class DurationType {
  kInfinity,
  kMinusInfinity,
  kZero,
  kNegative,
  kPositive
};

TEST(ArbitraryDurationTest, GeneratesAllTypesOfValues) {
  absl::flat_hash_set<DurationType> to_find = {
      DurationType::kInfinity, DurationType::kMinusInfinity,
      DurationType::kZero, DurationType::kNegative, DurationType::kPositive};
  auto domain = Arbitrary<absl::Duration>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/100, /*num_mutations=*/900);
  ASSERT_THAT(values, SizeIs(Ge(1000)));

  for (const auto& val : values) {
    if (val.user_value == absl::InfiniteDuration()) {
      to_find.erase(DurationType::kInfinity);
    } else if (val.user_value == -absl::InfiniteDuration()) {
      to_find.erase(DurationType::kMinusInfinity);
    } else if (val.user_value == absl::ZeroDuration()) {
      to_find.erase(DurationType::kZero);
    } else if (val.user_value < absl::ZeroDuration()) {
      to_find.erase(DurationType::kNegative);
    } else if (val.user_value > absl::ZeroDuration()) {
      to_find.erase(DurationType::kPositive);
    }
  }
  EXPECT_THAT(to_find, IsEmpty());
}

uint64_t AbsoluteValueOf(absl::Duration d) {
  auto [secs, ticks] = internal::GetSecondsAndTicks(d);
  if (secs == std::numeric_limits<int64_t>::min()) {
    return static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1 +
           ticks;
  }
  return static_cast<uint64_t>(std::abs(secs)) + ticks;
}

TEST(ArbitraryDurationTest, ShrinksCorrectly) {
  auto domain = Arbitrary<absl::Duration>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/100, /*num_mutations=*/900);
  ASSERT_THAT(values, SizeIs(Ge(1000)));

  ASSERT_TRUE(TestShrink(
                  domain, values,
                  [](auto v) {
                    return (v == absl::InfiniteDuration() ||
                            v == -absl::InfiniteDuration() ||
                            v == absl::ZeroDuration());
                  },
                  [](auto prev, auto next) {
                    // For values other than (-)inf, next is closer to zero,
                    // so the absolute value of next is less than that of prev
                    return ((prev == absl::InfiniteDuration() &&
                             next == absl::InfiniteDuration()) ||
                            (prev == -absl::InfiniteDuration() &&
                             next == -absl::InfiniteDuration()) ||
                            AbsoluteValueOf(next) < AbsoluteValueOf(prev));
                  })
                  .ok());
}

// Checks that indirect call to Arbitrary<absl::Duration> works.
TEST(ArbitraryDurationTest, ArbitraryVectorHasAllTypesOfValues) {
  absl::flat_hash_set<DurationType> to_find = {
      DurationType::kInfinity, DurationType::kMinusInfinity,
      DurationType::kZero, DurationType::kNegative, DurationType::kPositive};
  auto domain = Arbitrary<std::vector<absl::Duration>>();
  absl::flat_hash_set<Value<decltype(domain)>> values =
      GenerateValues(domain,
                     /*num_seeds=*/100, /*num_mutations=*/900);
  ASSERT_THAT(values, SizeIs(Ge(1000)));

  for (const auto& val : values) {
    if (val.user_value.empty()) continue;
    absl::Duration d = val.user_value[0];
    if (d == absl::InfiniteDuration()) {
      to_find.erase(DurationType::kInfinity);
    } else if (d == -absl::InfiniteDuration()) {
      to_find.erase(DurationType::kMinusInfinity);
    } else if (d == absl::ZeroDuration()) {
      to_find.erase(DurationType::kZero);
    } else if (d < absl::ZeroDuration()) {
      to_find.erase(DurationType::kNegative);
    } else if (d > absl::ZeroDuration()) {
      to_find.erase(DurationType::kPositive);
    }
  }
  EXPECT_THAT(to_find, IsEmpty());
}

TEST(ArbitraryTimeTest, InitGeneratesSeeds) {
  Domain<absl::Time> domain = Arbitrary<absl::Time>().WithSeeds(
      {absl::UnixEpoch() + absl::Seconds(42)});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, absl::UnixEpoch() + absl::Seconds(42))));
}

enum class TimeType {
  kInfinitePast,
  kInfiniteFuture,
  kUnixEpoch,
  kFiniteNonEpoch
};

TEST(ArbitraryTimeTest, GeneratesAllTypesOfValues) {
  absl::flat_hash_set<TimeType> to_find = {
      TimeType::kInfinitePast, TimeType::kInfiniteFuture, TimeType::kUnixEpoch,
      TimeType::kFiniteNonEpoch};
  auto domain = Arbitrary<absl::Time>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/100, /*num_mutations=*/900);
  ASSERT_THAT(values, SizeIs(Ge(1000)));

  for (const auto& val : values) {
    if (val.user_value == absl::InfinitePast()) {
      to_find.erase(TimeType::kInfinitePast);
    } else if (val.user_value == absl::InfiniteFuture()) {
      to_find.erase(TimeType::kInfiniteFuture);
    } else if (val.user_value == absl::UnixEpoch()) {
      to_find.erase(TimeType::kUnixEpoch);
    } else {
      to_find.erase(TimeType::kFiniteNonEpoch);
    }
  }
  EXPECT_THAT(to_find, IsEmpty());
}

TEST(ArbitraryTimeTest, ShrinksCorrectly) {
  auto domain = Arbitrary<absl::Time>();
  const auto values = GenerateValues(domain,
                                     /*num_seeds=*/100, /*num_mutations=*/900);
  ASSERT_THAT(values, SizeIs(Ge(1000)));

  ASSERT_TRUE(TestShrink(
                  domain, values,
                  [](auto v) {
                    return (v == absl::InfinitePast() ||
                            v == absl::InfiniteFuture() ||
                            v == absl::UnixEpoch());
                  },
                  [](auto prev, auto next) {
                    // For values other than inf, next is closer to epoch
                    return ((prev == absl::InfinitePast() &&
                             next == absl::InfinitePast()) ||
                            (prev == absl::InfiniteFuture() &&
                             next == absl::InfiniteFuture()) ||
                            AbsoluteValueOf(next - absl::UnixEpoch()) <
                                AbsoluteValueOf(prev - absl::UnixEpoch()));
                  })
                  .ok());
}

// Checks that indirect call to Arbitrary<absl::Time> works.
TEST(ArbitraryTimeTest, ArbitraryVectorHasAllTypesOfValues) {
  absl::flat_hash_set<TimeType> to_find = {
      TimeType::kInfinitePast, TimeType::kInfiniteFuture, TimeType::kUnixEpoch,
      TimeType::kFiniteNonEpoch};
  auto domain = Arbitrary<std::vector<absl::Time>>();
  absl::flat_hash_set<Value<decltype(domain)>> values =
      GenerateValues(domain,
                     /*num_seeds=*/100, /*num_mutations=*/900);
  ASSERT_THAT(values, SizeIs(Ge(1000)));

  for (const auto& val : values) {
    if (val.user_value.empty()) continue;
    absl::Time t = val.user_value[0];
    if (t == absl::InfinitePast()) {
      to_find.erase(TimeType::kInfinitePast);
    } else if (t == absl::InfiniteFuture()) {
      to_find.erase(TimeType::kInfiniteFuture);
    } else if (t == absl::UnixEpoch()) {
      to_find.erase(TimeType::kUnixEpoch);
    } else {
      to_find.erase(TimeType::kFiniteNonEpoch);
    }
  }
  EXPECT_THAT(to_find, IsEmpty());
}

TEST(ArbitraryStatusCodeTest, GeneratesAllValues) {
  absl::flat_hash_set<absl::StatusCode> to_find = {
      absl::StatusCode::kOk,
      absl::StatusCode::kCancelled,
      absl::StatusCode::kUnknown,
      absl::StatusCode::kInvalidArgument,
      absl::StatusCode::kDeadlineExceeded,
      absl::StatusCode::kNotFound,
      absl::StatusCode::kAlreadyExists,
      absl::StatusCode::kPermissionDenied,
      absl::StatusCode::kResourceExhausted,
      absl::StatusCode::kFailedPrecondition,
      absl::StatusCode::kAborted,
      absl::StatusCode::kOutOfRange,
      absl::StatusCode::kUnimplemented,
      absl::StatusCode::kInternal,
      absl::StatusCode::kUnavailable,
      absl::StatusCode::kDataLoss,
      absl::StatusCode::kUnauthenticated,
  };
  auto domain = Arbitrary<absl::StatusCode>();
  absl::BitGen prng;

  const int max_iterations = IterationsToHitAll(17, 1.0 / (4 * 17));
  for (int i = 0; i < max_iterations && !to_find.empty(); ++i) {
    to_find.erase(domain.GetRandomValue(prng));
  }

  EXPECT_THAT(to_find, IsEmpty());
}

TEST(ArbitraryStatusCodeTest, InitGeneratesSeeds) {
  Domain<absl::StatusCode> domain = Arbitrary<absl::StatusCode>().WithSeeds(
      {absl::StatusCode::kInvalidArgument});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, absl::StatusCode::kInvalidArgument)));
}

TEST(ArbitraryStatusTest, GeneratesOkAndError) {
  auto domain = Arbitrary<absl::Status>();
  absl::BitGen prng;
  bool found_ok = false;
  bool found_error = false;

  for (int i = 0; i < 100 && (!found_ok || !found_error); ++i) {
    absl::Status s = domain.GetRandomValue(prng);
    if (s.ok()) {
      found_ok = true;
    } else {
      found_error = true;
    }
  }

  EXPECT_TRUE(found_ok);
  EXPECT_TRUE(found_error);
}

TEST(ArbitraryStatusTest, InitGeneratesSeeds) {
  absl::Status seed = absl::InvalidArgumentError("seed message");
  Domain<absl::Status> domain = Arbitrary<absl::Status>().WithSeeds({seed});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, seed)));
}

TEST(ArbitraryStatusTest, FromValueAndGetValuePreserveCodeAndMessage) {
  auto domain = Arbitrary<absl::Status>();
  absl::Status status = absl::InvalidArgumentError("msg");
  status.SetPayload("some_url", absl::Cord("payload"));
  auto corpus_val = domain.FromValue(status);
  ASSERT_TRUE(corpus_val.has_value());
  absl::Status mapped_status = domain.GetValue(*corpus_val);
  EXPECT_EQ(mapped_status.code(), status.code());
  EXPECT_EQ(mapped_status.message(), status.message());
}

TEST(ArbitraryEnumTest, GeneratesAllValues) {
  enum class MyTestEnum { kValue0, kValue1, kValue2 };

  auto domain = Arbitrary<MyTestEnum>();
  absl::BitGen prng;
  absl::flat_hash_set<MyTestEnum> found;

  const int max_iterations = IterationsToHitAll(3, 1.0 / 3);
  for (int i = 0; i < max_iterations && found.size() < 3; ++i) {
    found.insert(domain.GetRandomValue(prng));
  }

  EXPECT_THAT(found,
              UnorderedElementsAre(MyTestEnum::kValue0, MyTestEnum::kValue1,
                                   MyTestEnum::kValue2));
}

}  // namespace
}  // namespace fuzztest
