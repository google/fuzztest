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

// Tests of domain `InRegexp`.

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/random/random.h"
#include "absl/types/span.h"
#include "./fuzztest/domain.h"
#include "./domain_tests/domain_testing.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/type_support.h"
#include "re2/re2.h"

namespace fuzztest {
namespace {

using ::testing::Contains;
using ::testing::Optional;
using ::testing::ResultOf;
using ::testing::StrEq;

TEST(InRegexp, InitGenerateDifferentValidAndShortValues) {
  absl::BitGen bitgen;
  static constexpr struct {
    const char* regexp_to_test;
    int n_unique_value;
    int expected_average_size;
  } kTestCases[] = {
      {"a\\w*b", 300, 6},
      {"A{2,10}", 9, 3},
      {"a*\\w*\\W*b+", 400, 5},
  };

  for (auto [regexp, num_unique_values, expected_average_size] : kTestCases) {
    absl::flat_hash_set<std::string> unique_values;
    auto domain = InRegexp(regexp);
    size_t total_size = 0;
    size_t generation_times = 0;

    while (unique_values.size() < num_unique_values) {
      ++generation_times;
      std::string val = domain.GetValue(domain.Init(bitgen));
      total_size += val.size();
      EXPECT_TRUE(RE2::FullMatch(val, regexp));
      unique_values.insert(val);
    }

    EXPECT_NEAR(expected_average_size,
                static_cast<double>(total_size) / generation_times, 1);
  }
}

TEST(InRegexp, InitGeneratesSeeds) {
  auto domain = InRegexp(R"re(a\w*b)re").WithSeeds({"a_Hello_World_b"});

  EXPECT_THAT(GenerateInitialValues(domain, 1000),
              Contains(Value(domain, "a_Hello_World_b")));
}

// TODO(changochen): Improve the tests to verify "close" mutation.
TEST(InRegexp, MutationGeneratesDifferentValidValues) {
  absl::BitGen bitgen;
  static constexpr struct {
    const char* regexp_to_test;
    int n_unique_value;
  } kTestCases[] = {
      {"", 1},
      {"aa[ab]b", 2},
      {"^df[a-z]\\wf$", 50},
      {"TestTest", 1},
      {"a\\w*b", 100},
      {"A{2,10}", 9},
      {"Sun[\\W]{3}Cool[\\d]{4}", 40},
  };

  for (auto [regexp, num_unique_values] : kTestCases) {
    absl::flat_hash_set<std::string> unique_values;
    Domain<std::string> domain = InRegexp(regexp);
    Value val(domain, bitgen);
    EXPECT_TRUE(RE2::FullMatch(val.user_value, regexp));

    while (unique_values.size() < num_unique_values) {
      val.Mutate(domain, bitgen, false);
      EXPECT_TRUE(RE2::FullMatch(val.user_value, regexp));
      unique_values.insert(val.user_value);
    }
  }
}

TEST(InRegexp, InvalidInputReportsErrors) {
  EXPECT_DEATH_IF_SUPPORTED(InRegexp("["), "Invalid RE2 regular expression.");
}

TEST(InRegexp, MutatingRepetitionCanIncreaseAndDecreaseLength) {
  absl::BitGen bitgen;

  auto domain = InRegexp("a*");
  Value val(domain, bitgen);
  std::vector<int> size_histogram(7, 0);
  constexpr int mutate_times = 50000;
  for (int i = 0; i < mutate_times; ++i) {
    val.corpus_value = domain.FromValue("aaaaa").value();
    val.Mutate(domain, bitgen, false);
    size_t size_after_mutation = val.user_value.size();
    ASSERT_LT(size_after_mutation, 7) << val.user_value;
    ++size_histogram[size_after_mutation];
  }

  // The expected ratio for adding a character is 50%, and the expected ration
  // for removing 0, 1, 2, 3, 4, 5 characters is 50%/6 = 8.3% respectively.
  constexpr double abs_diff = 0.01;
  constexpr double p_adding_one_char = 0.5;
  constexpr double p_removing_char_for_each_length = 0.5 / 6;
  for (int i = 0; i < 6; i++) {
    EXPECT_NEAR(static_cast<double>(size_histogram[i]) / mutate_times,
                p_removing_char_for_each_length, abs_diff);
  }
  EXPECT_NEAR(static_cast<double>(size_histogram[6]) / mutate_times,
              p_adding_one_char, abs_diff);
}

TEST(InRegexp, OnlyShrinkFindsDifferentValueWithMinimalLength) {
  absl::BitGen bitgen;
  static constexpr struct {
    const char* regexp_to_test;
    int expected_length;
    int unique_num;
    bool min_path_length_equal_min_string_length;
  } kTestCases[] = {
      {"a(c|d)+(e|f)+b", 4, 4, true},
      {"A{2,10}D{2,10}", 4, 1, true},
      {"A\\d+B\\w+C{2,5}", 6, 10, true},
      {"a([a|b][c|d]|efghi)o", 7, 1, false},
      {"(superlongstring|[ab][cd])(secondlongstring|[ef][gh])", 31, 1, false},
  };

  for (auto [regexp, expected_length, unique_num,
             min_path_length_equal_min_string_length] : kTestCases) {
    auto domain = InRegexp(regexp);
    absl::flat_hash_set<std::string> unique_values;
    while (unique_values.size() < unique_num) {
      Value val(domain, bitgen);
      while (val.user_value.size() != expected_length) {
        size_t pre_size = val.user_value.size();
        val.Mutate(domain, bitgen, /*only_shrink=*/true);
        if (min_path_length_equal_min_string_length) {
          ASSERT_LE(val.user_value.size(), pre_size) << val.user_value;
        }
        EXPECT_TRUE(RE2::FullMatch(val.user_value, regexp));
      }
      EXPECT_EQ(val.user_value.size(), expected_length);
      unique_values.insert(val.user_value);
    }
  }
}

struct InRegexString {
  std::string regexp;
  std::string string_in_domain;
};

using InRegexpTest = ::testing::TestWithParam<InRegexString>;
TEST_P(InRegexpTest, SerializationWorksCorrectly) {
  auto [regexp, string_in_domain] = GetParam();
  auto domain = InRegexp(regexp);
  auto corpus = domain.FromValue(string_in_domain);
  FUZZTEST_INTERNAL_CHECK(corpus.has_value(), "Invalid corpus");

  EXPECT_THAT(domain.ParseCorpus(domain.SerializeCorpus(*corpus)),
              Optional(ResultOf(
                  [&](const auto& parsed_corpus) {
                    return domain.GetValue(parsed_corpus);
                  },
                  StrEq(string_in_domain))));
}

INSTANTIATE_TEST_SUITE_P(RegexpSet, InRegexpTest,
                         testing::ValuesIn(std::vector<InRegexString>{
                             {"a(c|d)+(e|f)+b", "acceeb"},
                             {"A{2,10}D{2,10}", "AADD"},
                             {"A\\d+B\\w+C{2,5}", "A1BaCC"}}));

}  // namespace
}  // namespace fuzztest
