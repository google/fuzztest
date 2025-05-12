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

// Tests of character and string domains.

#include <cctype>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/random.h"
#include "./fuzztest/domain_core.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/table_of_recent_compares.h"

namespace fuzztest {
namespace {

using ::testing::AllOf;
using ::testing::Contains;
using ::testing::Each;
using ::testing::Eq;
using ::testing::Ge;
using ::testing::Gt;
using ::testing::HasSubstr;
using ::testing::IsTrue;
using ::testing::Lt;
using ::testing::Matches;
using ::testing::ResultOf;
using ::testing::SizeIs;

template <typename T>
class HandleTypeTest : public testing::Test {};

using HandleTypeTypes =
    testing::Types<std::string_view, std::vector<std::string_view>>;

TYPED_TEST_SUITE(HandleTypeTest, HandleTypeTypes, );

TYPED_TEST(HandleTypeTest, Arbitrary) {
  absl::BitGen bitgen;

  Domain<TypeParam> domain = Arbitrary<TypeParam>();

  // Handle types contain pointers/references to the corpus_type so we have to
  // handle them with care.
  // We use a std::deque to make sure we don't invalidate them.
  std::deque<Value<Domain<TypeParam>>> values;

  Set<TypeParam> unique;

  for (int i = 0; i < 100; ++i) {
    values.emplace_back(domain, bitgen);
    unique.insert(values.back().user_value);
  }

  VerifyRoundTripThroughConversion(values, domain);

  // Some minimal checking to make sure we are generating many values.
  EXPECT_THAT(unique, SizeIs(Gt(10)));
}

TYPED_TEST(HandleTypeTest, InitGeneratesSeeds) {
  auto domain = Arbitrary<TypeParam>();
  absl::BitGen bitgen;
  auto seed = Value(domain, bitgen);
  seed.RandomizeByRepeatedMutation(domain, bitgen);
  domain.WithSeeds({seed.user_value});

  EXPECT_THAT(GenerateInitialValues(domain, 1000), Contains(seed));
}

TEST(Domain, Forwarding) {
  absl::BitGen bitgen;

  Domain<char> domain = InRange('a', 'z');
  absl::flat_hash_set<char> elems;
  while (elems.size() < 'z' - 'a' + 1) {
    elems.insert(Value(domain, bitgen).user_value);
  }

  elems.clear();
  Value c(domain, bitgen);
  while (elems.size() < 'z' - 'a' + 1) {
    c.Mutate(domain, bitgen, {}, false);
    elems.insert(c.user_value);
  }
}

TEST(Domain, NonZeroChar) {
  CheckValues(GenerateValues(NonZeroChar()), [](char c) { return c != '\0'; });
}

TEST(Domain, NumericChar) {
  CheckValues(GenerateValues(NumericChar(), 5, 5),
              [](char c) { return std::isdigit(c); });
}

TEST(Domain, LowerChar) {
  CheckValues(GenerateValues(LowerChar(), 10, 10),
              [](char c) { return std::islower(c); });
}

TEST(Domain, UpperChar) {
  CheckValues(GenerateValues(UpperChar(), 10, 10),
              [](char c) { return std::isupper(c); });
}

TEST(Domain, AlphaChar) {
  CheckValues(GenerateValues(AlphaChar(), 20, 20),
              [](char c) { return std::isalpha(c); });
}

TEST(Domain, AlphaNumericChar) {
  CheckValues(GenerateValues(AlphaNumericChar(), 30, 30),
              [](char c) { return std::isalnum(c); });
}

TEST(Domain, PrintableAsciiChar) {
  CheckValues(GenerateValues(PrintableAsciiChar(), 40, 40),
              [](char c) { return std::isprint(c); });
}

TEST(Domain, AsciiChar) {
  CheckValues(GenerateValues(AsciiChar()), Matches(AllOf(Ge(0), Lt(128))));
}

TEST(Domain, AsciiString) {
  Domain<std::string> domain = AsciiString();
  for (const auto& value : GenerateValues(domain)) {
    for (int c : value.user_value) {
      ASSERT_GE(c, 0);
      ASSERT_LT(c, 128);
    }
  }
}

TEST(Domain, PrintableAsciiString) {
  Domain<std::string> domain = PrintableAsciiString();
  for (const auto& value : GenerateValues(domain)) {
    for (int c : value.user_value) {
      EXPECT_TRUE(isprint(c));
    }
  }
}

TEST(Domain, Utf8StringWorksWithSeeds) {
  auto domain = Utf8String().WithSeeds({"\u0414\u0430!\n"});
  EXPECT_THAT(GenerateValues(domain),
              Contains(Value(domain, "\u0414\u0430!\n")));
}

TEST(Domain, Utf8StringIgnoresInvalideSeeds) {
  const std::string invalid_utf8 = "abc\x80";
  EXPECT_THAT(Utf8String().FromValue(invalid_utf8), Eq(std::nullopt));
}

TEST(Domain, Utf8StringUsesDictionary) {
  auto domain = Utf8String();
  internal::TablesOfRecentCompares cmp_tables;
  // Fill the table with the same entry.
  for (int i = 0; i < cmp_tables.GetMutable<0>().kTableSize; ++i) {
    cmp_tables.GetMutable<0>().Insert(reinterpret_cast<const uint8_t*>("abcd"),
                                      reinterpret_cast<const uint8_t*>("1234"),
                                      4);
  }

  absl::BitGen bitgen;
  std::vector<std::string> mutants;
  const double hit_probability =  //
      1.0 / 2                     // to pick String() within OverlapOf(...)
      * 1.0 / 4                   // to use dictionaries
      * 1.0 / 4                   // to use cmp tables
      * 1.0 / 2;                  // to pick the memcmp table
  for (int i = 0; i < IterationsToHitAll(/*num_cases=*/1, hit_probability);
       ++i) {
    auto mutant = domain.FromValue("abcd");
    ASSERT_TRUE(mutant.has_value());
    domain.Mutate(*mutant, bitgen, {/*cmp_tables=*/&cmp_tables}, false);
    mutants.push_back(domain.GetValue(*mutant));
  }
  EXPECT_THAT(mutants, Contains(HasSubstr("1234")));
}

TEST(Domain, AsciiStringUsesDictionary) {
  auto domain = AsciiString();
  internal::TablesOfRecentCompares cmp_tables;
  // Fill the table with the same entry.
  for (int i = 0; i < cmp_tables.GetMutable<0>().kTableSize; ++i) {
    cmp_tables.GetMutable<0>().Insert(reinterpret_cast<const uint8_t*>("abcd"),
                                      reinterpret_cast<const uint8_t*>("1234"),
                                      4);
  }

  absl::BitGen bitgen;
  std::vector<std::string> mutants;
  const double hit_probability =  //
      1.0 / 4                     // to use dictionaries
      * 1.0 / 4                   // to use cmp tables
      * 1.0 / 2;                  // to pick the memcmp table
  for (int i = 0; i < IterationsToHitAll(/*num_cases=*/1, hit_probability);
       ++i) {
    auto mutant = domain.FromValue("abcd");
    ASSERT_TRUE(mutant.has_value());
    domain.Mutate(*mutant, bitgen, {/*cmp_tables=*/&cmp_tables}, false);
    mutants.push_back(domain.GetValue(*mutant));
  }
  EXPECT_THAT(mutants, Contains(HasSubstr("1234")));
}

}  // namespace
}  // namespace fuzztest
