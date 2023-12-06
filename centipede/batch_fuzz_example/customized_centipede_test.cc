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

#include "./centipede/batch_fuzz_example/customized_centipede.h"

#include <string>
#include <string_view>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./centipede/defs.h"
#include "./centipede/environment.h"
#include "./centipede/runner_result.h"
#include "./centipede/test_util.h"

namespace centipede {
namespace {

using ::testing::AllOf;
using ::testing::Each;
using ::testing::IsEmpty;
using ::testing::Property;
using ::testing::SizeIs;
using ::testing::UnorderedElementsAreArray;

bool RunInputsAndCollectCoverage(const Environment &env,
                                 const std::vector<std::string> &inputs,
                                 BatchResult &batch_result) {
  CustomizedCallbacks customized_callbacks(env);

  // Repackage string inputs into ByteArray inputs.
  std::vector<ByteArray> byte_array_inputs;
  for (const auto &string_input : inputs) {
    byte_array_inputs.emplace_back(string_input.cbegin(), string_input.cend());
  }
  // Run.
  return customized_callbacks.Execute(env.binary, byte_array_inputs,
                                      batch_result);
}

std::string GetTargetPath() {
  return GetDataDependencyFilepath(
      "centipede/batch_fuzz_example/batch_fuzz_target");
}

TEST(BatchFuzz, SucceedsToCollectCoverageForTwoInputs) {
  Environment env;
  env.binary = GetTargetPath();
  BatchResult batch_result;
  ASSERT_TRUE(RunInputsAndCollectCoverage(env, {"a", "b"}, batch_result));
  EXPECT_THAT(batch_result.results(),
              AllOf(SizeIs(2), Each(Property(&ExecutionResult::features,
                                             Not(IsEmpty())))));
}

TEST(BatchFuzz, CollectsTheSameCoverageForSameInputs) {
  Environment env;
  env.binary = GetTargetPath();
  BatchResult batch_result;
  ASSERT_TRUE(RunInputsAndCollectCoverage(env, {"f", "f"}, batch_result));
  ASSERT_THAT(batch_result.results(),
              AllOf(SizeIs(2), Each(Property(&ExecutionResult::features,
                                             Not(IsEmpty())))));
  EXPECT_THAT(batch_result.results()[0].features(),
              UnorderedElementsAreArray(batch_result.results()[1].features()));
}

}  // namespace
}  // namespace centipede
