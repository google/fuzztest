// Copyright 2025 The Centipede Authors.
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

#include "./common/crashing_input_filename.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace fuzztest::internal {
namespace {

using ::testing::FieldsAre;

TEST(ParseCrashingInputFilenameTest, ParsesFileNameWithOnlyInputSignature) {
  auto components = ParseCrashingInputFilename("input_signature");
  ASSERT_TRUE(components.ok());
  EXPECT_THAT(*components, FieldsAre(/*bug_id=*/"input_signature",
                                     /*crash_signature=*/"",
                                     /*input_signature=*/"input_signature"));
}

TEST(ParseCrashingInputFilenameTest, FailsOnInvalidFileName) {
  EXPECT_FALSE(ParseCrashingInputFilename("single-dash").ok());
}

TEST(ParseCrashingInputFilenameTest, ParsesFileNameWithAllComponents) {
  auto components = ParseCrashingInputFilename(
      "id-with-dash-crash_signature-input_signature");
  ASSERT_TRUE(components.ok());
  EXPECT_THAT(*components, FieldsAre(/*bug_id=*/"id-with-dash",
                                     /*crash_signature=*/"crash_signature",
                                     /*input_signature=*/"input_signature"));
}

}  // namespace
}  // namespace fuzztest::internal
