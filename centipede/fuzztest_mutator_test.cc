// Copyright 2023 The Centipede Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./centipede/fuzztest_mutator.h"

#include <cstddef>
#include <limits>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_join.h"
#include "./centipede/defs.h"

namespace centipede {

namespace {

using ::testing::AllOf;
using ::testing::Each;
using ::testing::Le;
using ::testing::SizeIs;
using ::testing::Values;

TEST(FuzzTestMutator, DifferentRngSeedsLeadToDifferentMutantSequences) {
  FuzzTestMutator mutator[2]{FuzzTestMutator(/*seed=*/1),
                             FuzzTestMutator(/*seed=*/2)};

  std::vector<ByteArray> res[2];
  for (size_t i = 0; i < 2; i++) {
    ByteArray data = {0};
    std::vector<MutationInputRef> mutation_inputs = {{.data = data}};
    std::vector<ByteArray> mutants;
    constexpr size_t kMutantSequenceLength = 100;
    for (size_t iter = 0; iter < kMutantSequenceLength; iter++) {
      mutator[i].MutateMany(mutation_inputs, 1, mutants);
      ASSERT_EQ(mutants.size(), 1);
      res[i].push_back(mutants[0]);
    }
  }
  EXPECT_NE(res[0], res[1]);
}

TEST(FuzzTestMutator, MutateManyWorksWithInputsLargerThanMaxLen) {
  constexpr size_t kMaxLen = 4;
  FuzzTestMutator mutator(/*seed=*/1);
  EXPECT_TRUE(mutator.set_max_len(kMaxLen));
  constexpr size_t kNumMutantsToGenerate = 10000;
  std::vector<ByteArray> mutants;

  mutator.MutateMany(
      {
          {.data = {0, 1, 2, 3, 4, 5, 6, 7}},
          {.data = {0}},
          {.data = {0, 1}},
          {.data = {0, 1, 2}},
          {.data = {0, 1, 2, 3}},
      },
      kNumMutantsToGenerate, mutants);

  EXPECT_THAT(mutants,
              AllOf(SizeIs(kNumMutantsToGenerate), Each(SizeIs(Le(kMaxLen)))));
}

// Test parameter containing the mutation settings and the expectations of a
// single mutation step.
struct MutationStepTestParameter {
  // The input to be mutated.
  ByteArray seed_input;
  // The set of mutants to be expected by mutating `seed_input`.
  absl::flat_hash_set<ByteArray> expected_mutants;
  // The set of mutants not supposed to be seen by mutating `seed_input`.
  absl::flat_hash_set<ByteArray> unexpected_mutants;
  // The max length of the mutants. If unset, will not set the limit.
  std::optional<size_t> max_len;
  // The mutation dictionary.
  std::vector<ByteArray> dictionary;
  // The comparison data following the format of ExecutionMetadata::cmp_data.
  ByteArray cmp_data;
  // The minimum number of iterations regardless of whether all mutants in
  // `expected_mutants` are found or not.
  size_t min_num_iterations = 1000;
  // The maximum number of iterations to try before all mutants in
  // `expected_mutants` are found.
  size_t max_num_iterations = 100000000;
};

class MutationStepTest
    : public testing::TestWithParam<MutationStepTestParameter> {};

TEST_P(MutationStepTest, GeneratesExpectedMutantsAndAvoidsUnexpectedMutants) {
  FuzzTestMutator mutator(/*seed=*/1);
  ASSERT_LE(GetParam().min_num_iterations, GetParam().max_num_iterations);
  if (GetParam().max_len.has_value())
    EXPECT_TRUE(mutator.set_max_len(*GetParam().max_len));
  mutator.AddToDictionary(GetParam().dictionary);
  absl::flat_hash_set<ByteArray> unmatched_expected_mutants =
      GetParam().expected_mutants;
  const auto& unexpected_mutants = GetParam().unexpected_mutants;
  ExecutionMetadata metadata = {.cmp_data = GetParam().cmp_data};
  const std::vector<MutationInputRef> inputs = {
      {.data = GetParam().seed_input, .metadata = &metadata}};
  std::vector<ByteArray> mutants;
  for (size_t i = 0; i < GetParam().max_num_iterations; i++) {
    mutator.MutateMany(inputs, 1, mutants);
    ASSERT_EQ(mutants.size(), 1);
    const auto& mutant = mutants[0];
    EXPECT_FALSE(unexpected_mutants.contains(mutant))
        << "Unexpected mutant: {" << absl::StrJoin(mutant, ",") << "}";
    unmatched_expected_mutants.erase(mutant);
    if (unmatched_expected_mutants.empty() &&
        i >= GetParam().min_num_iterations)
      break;
  }
  EXPECT_TRUE(unmatched_expected_mutants.empty());
}

INSTANTIATE_TEST_SUITE_P(InsertByteUpToMaxLen, MutationStepTest,
                         Values(MutationStepTestParameter{
                             .seed_input = {0, 1, 2},
                             .expected_mutants =
                                 {
                                     {0, 1, 2, 3},
                                     {0, 3, 1, 2},
                                     {3, 0, 1, 2},
                                 },
                             .unexpected_mutants =
                                 {
                                     {0, 1, 2, 3, 4},
                                     {0, 3, 4, 1, 2},
                                     {3, 4, 0, 1, 2},
                                 },
                             .max_len = 4,
                         }));

INSTANTIATE_TEST_SUITE_P(OverwriteFromDictionary, MutationStepTest,
                         Values(MutationStepTestParameter{
                             .seed_input = {1, 2, 3, 4, 5},
                             .expected_mutants =
                                 {
                                     {1, 2, 7, 8, 9},
                                     {1, 7, 8, 9, 5},
                                     {7, 8, 9, 4, 5},
                                     {1, 2, 3, 0, 6},
                                     {1, 2, 0, 6, 5},
                                     {1, 0, 6, 4, 5},
                                     {0, 6, 3, 4, 5},
                                     {42, 2, 3, 4, 5},
                                     {1, 42, 3, 4, 5},
                                     {1, 2, 42, 4, 5},
                                     {1, 2, 3, 42, 5},
                                     {1, 2, 3, 4, 42},
                                 },
                             .dictionary =
                                 {
                                     {7, 8, 9},
                                     {0, 6},
                                     {42},
                                 },
                         }));

INSTANTIATE_TEST_SUITE_P(
    OverwriteFromCmpDictionary, MutationStepTest,
    Values(MutationStepTestParameter{
        .seed_input = {1, 2, 40, 50, 60},
        .expected_mutants =
            {
                {3, 4, 40, 50, 60},
                {1, 2, 10, 20, 30},
            },
        .cmp_data = {/*size*/ 2, /*lhs*/ 1, 2, /*rhs*/ 3, 4, /*size*/ 3,
                     /*lhs*/ 10, 20, 30, /*rhs*/ 40, 50, 60},
    }));

INSTANTIATE_TEST_SUITE_P(InsertFromDictionary, MutationStepTest,
                         Values(MutationStepTestParameter{
                             .seed_input = {1, 2, 3},
                             .expected_mutants =
                                 {
                                     {1, 2, 3, 4, 5},
                                     {1, 2, 4, 5, 3},
                                     {1, 4, 5, 2, 3},
                                     {4, 5, 1, 2, 3},
                                     {1, 2, 3, 6, 7, 8},
                                     {1, 2, 6, 7, 8, 3},
                                     {1, 6, 7, 8, 2, 3},
                                     {6, 7, 8, 1, 2, 3},
                                 },
                             .dictionary =
                                 {
                                     {4, 5},
                                     {6, 7, 8},
                                 },
                         }));

INSTANTIATE_TEST_SUITE_P(InsertFromCmpDictionary, MutationStepTest,
                         Values(MutationStepTestParameter{
                             .seed_input = {1, 2, 3},
                             .expected_mutants =
                                 {
                                     {1, 2, 3, 4, 5},
                                     {1, 2, 4, 5, 3},
                                     {1, 4, 5, 2, 3},
                                     {4, 5, 1, 2, 3},
                                     {1, 2, 3, 6, 7, 8},
                                     {1, 2, 6, 7, 8, 3},
                                     {1, 6, 7, 8, 2, 3},
                                     {6, 7, 8, 1, 2, 3},
                                 },
                             .cmp_data = {/*size*/ 2, /*lhs*/ 4, 5, /*rhs*/ 4,
                                          5, /*size*/ 3,
                                          /*lhs*/ 6, 7, 8, /*rhs*/ 6, 7, 8},
                         }));

INSTANTIATE_TEST_SUITE_P(
    SkipsLongCmpEntry, MutationStepTest,
    Values(MutationStepTestParameter{
        .seed_input = {0},
        .expected_mutants =
            {
                {0, 1, 2, 3, 4},
            },
        .unexpected_mutants =
            {
                {0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10,
                 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
            },
        .cmp_data = {/*size*/ 20, /*lhs*/ 1, 2,  3,  4,  5,         6,
                     7,           8,         9,  10, 11, 12,        13,
                     14,          15,        16, 17, 18, 19,        20,
                     /*rhs*/ 1,   2,         3,  4,  5,  6,         7,
                     8,           9,         10, 11, 12, 13,        14,
                     15,          16,        17, 18, 19, 20,
                     /*size*/ 4,  /*lhs*/ 1, 2,  3,  4,  /*rhs*/ 1, 2,
                     3,           4}}));

}  // namespace

}  // namespace centipede
