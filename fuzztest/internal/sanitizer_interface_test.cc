// Copyright 2025 Google LLC
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

#include "./fuzztest/internal/sanitizer_interface.h"

#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"

namespace fuzztest::internal {
namespace {

using ::testing::HasSubstr;

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeWhenItIsTheOnlyToken) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: SomeSanitizer: some-crash-type");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "some-crash-type");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeWhenFilePathIsPresent) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: AddressSanitizer: heap-use-after-free some/file.cc:1234:5");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "heap-use-after-free");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, ParsesMemoryLeak) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: AddressSanitizer: 10 byte(s) leaked in 10 allocation(s)");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "memory-leak");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, ExtractsCrashTypeForUBSan) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: UndefinedBehaviorSanitizer: null-pointer-use "
          "some/file.h:32:7");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "null-pointer-use");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, ExtractsCrashTypeForMSan) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: MemorySanitizer: use-of-uninitialized-value "
          "some/file.cc:570:11 in SomeFunction");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "use-of-uninitialized-value");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, FailsOnMissingSummaryPrefix) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary("Missing SUMMARY prefix");
  ASSERT_FALSE(crash_type.ok());
  EXPECT_THAT(crash_type.status().message(),
              HasSubstr("Missing SUMMARY prefix"));
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, FailsOnMissingSanitizerName) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary("SUMMARY: No sanitizer name");
  ASSERT_FALSE(crash_type.ok());
  EXPECT_THAT(crash_type.status().message(), HasSubstr("No sanitizer name"));
}

}  // namespace
}  // namespace fuzztest::internal
