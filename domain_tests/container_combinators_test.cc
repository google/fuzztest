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

#include <array>
#include <cstdio>
#include <initializer_list>
#include <list>
#include <map>
#include <set>
#include <string>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/random.h"
#include "absl/strings/str_cat.h"
#include "./fuzztest/domain_core.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/meta.h"

namespace fuzztest {
namespace {

using ::testing::_;
using ::testing::AllOf;
using ::testing::Contains;
using ::testing::Each;
using ::testing::ElementsAre;
using ::testing::FieldsAre;
using ::testing::Ge;
using ::testing::Gt;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Le;
using ::testing::MatchesRegex;
using ::testing::Pair;
using ::testing::SizeIs;

TEST(ContainerCombinatorTest, ValueTypeOfListContainerIsInferred) {
  for (const auto& value :
       GenerateValues(ContainerOf<std::list>(Positive<int>()).WithSize(3))) {
    static_assert(std::is_same_v<decltype(value.user_value), std::list<int>>);
    ASSERT_THAT(value.user_value, SizeIs(3));
    ASSERT_THAT(value.user_value, Each(Ge(1)));
  }
}

TEST(ContainerCombinatorTest, ValueTypeOfVectorContainerIsInferred) {
  for (const auto& value :
       GenerateValues(ContainerOf<std::vector>(InRange(-6.0F, 6.0F))
                          .WithMinSize(2)
                          .WithMaxSize(5))) {
    static_assert(
        std::is_same_v<decltype(value.user_value), std::vector<float>>);
    ASSERT_THAT(value.user_value, SizeIs(IsInClosedRange(2, 5)));
    ASSERT_THAT(value.user_value, Each(IsInClosedRange(-6.0, 6.0)));
  }
}

TEST(ContainerCombinatorTest, ValueTypeOfSetContainerIsInferred) {
  for (const auto& value : GenerateValues(
           ContainerOf<std::set>(NonEmpty(PrintableAsciiString())))) {
    static_assert(
        std::is_same_v<decltype(value.user_value), std::set<std::string>>);
    ASSERT_THAT(
        value.user_value,                             // Each string in the set
        Each(AllOf(Not(IsEmpty()),                    // is not empty, and each
                   Each(                              // character in it is
                       IsInClosedRange(32, 126)))));  // printable ASCII.
  }
}

TEST(ContainerCombinatorTest, MinSizeCanBeLargerThanDefaultMaxSize) {
  static constexpr size_t kDefaultMaxSize = 1000;
  auto domain = ContainerOf<std::vector>(Arbitrary<int>())
                    .WithMinSize(kDefaultMaxSize + 1);
  absl::BitGen bitgen;
  auto val = Value(domain, bitgen);
  val.Mutate(domain, bitgen, {}, false);
  ASSERT_THAT(val.user_value, SizeIs(Gt(kDefaultMaxSize)));
}

TEST(ContainerCombinatorTest, FailsWithInconsistentMinAndMaxSizes) {
  EXPECT_DEATH_IF_SUPPORTED(
      ContainerOf<std::vector>(Arbitrary<int>())
          .WithMinSize(100)
          .WithMaxSize(99),
      "Maximal size 99 cannot be smaller than minimal size 100");
  EXPECT_DEATH_IF_SUPPORTED(
      ContainerOf<std::vector>(Arbitrary<int>())
          .WithMaxSize(100)
          .WithMinSize(101),
      "Minimal size 101 cannot be larger than maximal size 100");
}

TEST(SequencedContainerTest, InitGeneratesSeeds) {
  auto domain =
      ContainerOf<std::vector>(Arbitrary<int>()).WithSeeds({{1, 3, 3, 7}});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, {1, 3, 3, 7})));
}

TEST(AssociativeContainerTest, InitGeneratesSeeds) {
  auto domain = ContainerOf<absl::flat_hash_map<std::string, int>>(
                    PairOf(Arbitrary<std::string>(), Arbitrary<int>()))
                    .WithSeeds({{{"hello", 7}, {"world", 42}}});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, {{"hello", 7}, {"world", 42}})));
}

TEST(ContainerCombinatorTest, VectorOf) {
  for (const auto& value : GenerateValues(VectorOf(InRange(-5, 5)))) {
    ASSERT_THAT(value.user_value, Each(IsInClosedRange(-5, 5)));
  }
}

TEST(ContainerCombinatorTest, DequeOf) {
  for (const auto& value : GenerateValues(DequeOf(InRange(-5, 5)))) {
    ASSERT_THAT(value.user_value, Each(IsInClosedRange(-5, 5)));
  }
}

TEST(ContainerCombinatorTest, ListOf) {
  for (const auto& value : GenerateValues(ListOf(InRange(-5, 5)))) {
    ASSERT_THAT(value.user_value, Each(IsInClosedRange(-5, 5)));
  }
}

TEST(ContainerCombinatorTest, SetOf) {
  for (const auto& value :
       GenerateValues(SetOf(InRange(-10, 50)).WithMaxSize(5))) {
    static_assert(std::is_same_v<decltype(value.user_value), std::set<int>>);
    ASSERT_THAT(value.user_value, SizeIs(Le(5)));
    ASSERT_THAT(value.user_value, Each(IsInClosedRange(-10, 50)));
  }
}

TEST(ContainerCombinatorTest, MapOf) {
  auto key_domain = InRange(1, 1000);
  auto value_domain = InRange(-500.0F, 0.0F);
  for (const auto& value :
       GenerateValues(MapOf(std::move(key_domain), std::move(value_domain))
                          .WithMaxSize(50))) {
    static_assert(
        std::is_same_v<decltype(value.user_value), std::map<int, float>>);
    ASSERT_THAT(value.user_value, SizeIs(Le(50)));
    ASSERT_THAT(value.user_value, Each(Pair(IsInClosedRange(1, 1000),
                                            IsInClosedRange(-500.0F, 0.0F))));
  }
}

TEST(ContainerCombinatorTest, UnorderedSetOf) {
  for (const auto& value :
       GenerateValues(UnorderedSetOf(InRange(100, 1000)).WithMaxSize(5))) {
    static_assert(
        std::is_same_v<decltype(value.user_value), std::unordered_set<int>>);
    ASSERT_THAT(value.user_value, Each(IsInClosedRange(100, 1000)));
  }
}

TEST(ContainerCombinatorTest, UnorderedMapOf) {
  auto key_domain = InRange(-500.0F, 0.0F);
  auto value_domain = InRange(1, 1000);
  for (const auto& value : GenerateValues(
           UnorderedMapOf(std::move(key_domain), std::move(value_domain))
               .WithMinSize(10)
               .WithMaxSize(50))) {
    static_assert(std::is_same_v<decltype(value.user_value),
                                 std::unordered_map<float, int>>);
    ASSERT_THAT(value.user_value, SizeIs(IsInClosedRange(10, 50)));
    ASSERT_THAT(value.user_value, Each(Pair(IsInClosedRange(-500.0F, 0.0F),
                                            IsInClosedRange(1, 1000))));
  }
}

TEST(ContainerCombinatorTest, FlatHashMap) {
  auto key_domain = InRange(-500.0F, 0.0F);
  auto value_domain = InRange(1, 1000);
  for (const auto& value : GenerateValues(
           ContainerOf<absl::flat_hash_map<float, int>>(
               PairOf(std::move(key_domain), std::move(value_domain)))
               .WithMinSize(10)
               .WithMaxSize(50))) {
    static_assert(std::is_same<decltype(value.user_value),
                               absl::flat_hash_map<float, int>>::value);
    ASSERT_THAT(value.user_value, Each(Pair(IsInClosedRange(-500.0F, 0.0F),
                                            IsInClosedRange(1, 1000))));
  }
}

MATCHER(ElementsAreUnique, absl::StrCat(negation ? "has duplicate elements"
                                                 : "has unique elements")) {
  // Note that we avoid using testing::IsSubsetOf(some_values) here because it
  // isn't optimized for some_values being an associative collection of values.
  using ArgT = std::remove_reference_t<decltype(arg)>;
  absl::flat_hash_set<internal::value_type_t<ArgT>> copy(arg.begin(),
                                                         arg.end());
  return arg.size() == copy.size();
}

TEST(ContainerCombinatorTest, UniqueElementsContainerOf) {
  // An std::unordered_multiset<T> can contain multiple elements with the same
  // value, but let's say our testing would benefit from limiting it to a single
  // element with each value; we could use UniqueElementsContainerOf to produce
  // just such a domain of std::unordered_multiset<T> values.
  for (const auto& value :
       GenerateValues(UniqueElementsContainerOf<std::unordered_multiset<int>>(
                          InRange(1, 100))
                          .WithSize(7))) {
    static_assert(std::is_same_v<decltype(value.user_value),
                                 std::unordered_multiset<int>>);
    ASSERT_THAT(value.user_value, SizeIs(7));
    ASSERT_THAT(value.user_value, Each(IsInClosedRange(1, 100)));
  }
}

TEST(UniqueElementsContainerTest, InitGeneratesSeeds) {
  auto domain =
      UniqueElementsContainerOf<std::unordered_multiset<int>>(Arbitrary<int>())
          .WithSeeds({{1, 3, 7}});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, {1, 3, 7})));
}

TEST(ContainerCombinatorTest, UniqueElementsVectorOf) {
  for (const auto& value : GenerateValues(
           UniqueElementsVectorOf(InRange(100, 1000)).WithMaxSize(5))) {
    static_assert(std::is_same_v<decltype(value.user_value), std::vector<int>>);
    ASSERT_THAT(value.user_value, SizeIs(Le(5)));
    ASSERT_THAT(value.user_value, Each(IsInClosedRange(100, 1000)));
    ASSERT_THAT(value.user_value, ElementsAreUnique());
  }
}

TEST(ContainerCombinatorTest, UniqueElementsVectorOfElementOf) {
  const std::initializer_list<std::string> candidates{
      "bonjour", "ciao", "g'day mate", "guten tag",  "hallo",
      "hello",   "hi",   "hola",       "konnichiwa", "marhaba",
      "namaste", "olá",  "salaam",     "salve",      "szia"};
  const absl::flat_hash_set<std::string> candidates_set(candidates.begin(),
                                                        candidates.end());
  const auto inner_domain = ElementOf(candidates);
  for (const auto& value : GenerateValues(UniqueElementsVectorOf(inner_domain)
                                              .WithMinSize(1)
                                              .WithMaxSize(2))) {
    static_assert(
        std::is_same_v<decltype(value.user_value), std::vector<std::string>>);
    ASSERT_THAT(value.user_value, SizeIs(IsInClosedRange(1, 2)));
    ASSERT_THAT(value.user_value, ElementsAreUnique());
    for (const auto& elem : value.user_value) {
      ASSERT_THAT(candidates_set, Contains(elem));
    }
  }
}

TEST(ContainerCombinatorTest, UniqueElementsVectorOfVectorOfInt) {
  auto elements_domain = VectorOf(InRange(500, 1000)).WithSize(3);
  auto domain = UniqueElementsVectorOf(elements_domain).WithSize(4);
  for (const auto& value : GenerateValues(domain)) {
    static_assert(std::is_same_v<decltype(value.user_value),
                                 std::vector<std::vector<int>>>);
    ASSERT_THAT(value.user_value, SizeIs(4));
    ASSERT_THAT(value.user_value, ElementsAreUnique());
    ASSERT_THAT(value.user_value,
                Each(AllOf(SizeIs(3), Each(IsInClosedRange(500, 1000)))));
  }
}

TEST(UniqueElementsVectorOf, ValidationRejectsInvalidValue) {
  absl::BitGen bitgen;

  auto domain_a = UniqueElementsVectorOf(InRange(0, 9)).WithMinSize(1);
  auto domain_b = UniqueElementsVectorOf(InRange(10, 19)).WithMinSize(1);

  Value value_a(domain_a, bitgen);
  Value value_b(domain_b, bitgen);

  ASSERT_OK(domain_a.ValidateCorpusValue(value_a.corpus_value));
  ASSERT_OK(domain_b.ValidateCorpusValue(value_b.corpus_value));

  EXPECT_THAT(
      domain_a.ValidateCorpusValue(value_b.corpus_value),
      IsInvalid(MatchesRegex(
          R"(Invalid value in container at index 0 >> The value .+ is not InRange\(0, 9\))")));
  EXPECT_THAT(
      domain_b.ValidateCorpusValue(value_a.corpus_value),
      IsInvalid(MatchesRegex(
          R"(Invalid value in container at index 0 >> The value .+ is not InRange\(10, 19\))")));
}

TEST(UniqueElementsVectorOf, ValidationRejectsNonUniqueElements) {
  auto domain = UniqueElementsVectorOf(InRange(1, 10));
  Value value(domain, {1, 2, 2, 3});

  EXPECT_THAT(
      domain.ValidateCorpusValue(value.corpus_value),
      IsInvalid(HasSubstr(R"(The container doesn't have unique elements)")));
}

TEST(UniqueElementsVectorOf, VerifyRoundTripThroughConversion) {
  auto domain = UniqueElementsVectorOf(InRange(100, 1000)).WithMaxSize(5);
  VerifyRoundTripThroughConversion(GenerateValues(domain), domain);
}

TEST(ContainerCombinatorTest, ArrayOfOne) {
  // A domain of std::array<T, 1> values can be defined in two ways:
  auto with_explicit_size = ArrayOf<1>(InRange(0.0, 1.0));
  auto with_inferred_size = ArrayOf(InRange(0.0, 1.0));

  for (const auto& value : GenerateValues(with_explicit_size)) {
    static_assert(
        std::is_same_v<decltype(value.user_value), std::array<double, 1>>);
    ASSERT_THAT(value.user_value[0], IsInClosedRange(0.0, 1.0));
  }

  for (const auto& value : GenerateValues(with_inferred_size)) {
    static_assert(
        std::is_same_v<decltype(value.user_value), std::array<double, 1>>);
    ASSERT_THAT(value.user_value[0], IsInClosedRange(0.0, 1.0));
  }
}

TEST(ContainerCombinatorTest, ArrayOfTwoFromTwoDomains) {
  // Define a domain of std::array<T, 2> values, where each element comes from a
  // different domain, though of course both domains produce values of the same
  // type.
  for (const auto& value :
       GenerateValues(ArrayOf(InRange(1900, 2022), InRange(1, 12)))) {
    ASSERT_THAT(value.user_value,
                AllOf(SizeIs(2), ElementsAre(IsInClosedRange(1900, 2022),
                                             IsInClosedRange(1, 12))));
  }
}

TEST(ContainerCombinatorTest, ArrayOfThreeFromOneDomain) {
  for (const auto& value : GenerateValues(ArrayOf<3>(InRange(-0.5, 0.5)))) {
    using array_type = decltype(value.user_value);
    static_assert(std::is_same_v<array_type, std::array<double, 3>>);
    ASSERT_THAT(value.user_value,
                AllOf(SizeIs(3), Each(IsInClosedRange(-0.5, 0.5))));
  }
}

TEST(Domain, Container) {
  Domain<std::vector<int>> domain =
      ContainerOf<std::vector<int>>(InRange(1, 100));
  for (const auto& value : GenerateValues(domain)) {
    for (auto i : value.user_value) {
      ASSERT_GE(i, 1);
      ASSERT_LE(i, 100);
    }
  }
}

TEST(TupleOf, GeneratesValidValues) {
  auto values = MutateUntilFoundN(TupleOf(InRange(-5, 5), AsciiChar()), 100);
  EXPECT_THAT(values, Each(FieldsAre(_, FieldsAre(IsInClosedRange(-5, 5),
                                                  IsInClosedRange(0, 127)))));
}

TEST(TupleOf, InitGeneratesSeeds) {
  auto domain = TupleOf(Arbitrary<int>(), Arbitrary<std::string>())
                    .WithSeeds({{42, "hello"}});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, {42, "hello"})));
}

TEST(PairOf, GeneratesValidValues) {
  auto values = MutateUntilFoundN(PairOf(InRange(-5, 5), AsciiChar()), 100);
  EXPECT_THAT(values, Each(FieldsAre(_, FieldsAre(IsInClosedRange(-5, 5),
                                                  IsInClosedRange(0, 127)))));
}

TEST(PairOf, InitGeneratesSeeds) {
  auto domain = PairOf(Arbitrary<int>(), Arbitrary<std::string>())
                    .WithSeeds({{42, "hello"}});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, {42, "hello"})));
}

}  // namespace
}  // namespace fuzztest
