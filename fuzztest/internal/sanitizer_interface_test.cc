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

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanDataRaceOnVptr) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: data race on vptr (ctor/dtor vs virtual "
          "call) some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "data-race");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, ExtractsCrashTypeForTSanDataRace) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: data race "
          "some/file.cc:33:37 in operator()");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "data-race");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanDestroyLocked) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: destroy of a locked mutex "
          "some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "destroy-locked-mutex");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanDoubleLock) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: double lock of a mutex some/file.cc:12:34 "
          "in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "double-lock-of-mutex");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, ExtractsCrashTypeForTSanDeadlock) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: lock-order-inversion (potential "
          "deadlock) some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "lock-order-inversion");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanMutexHeldWrongContext) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: mutex held in the wrong context "
          "some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "mutex-held-in-wrong-context");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanExternalRace) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: race on external object "
          "some/file.cc:12:34 "
          "in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "data-race");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanBadReadLock) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: read lock of a write locked mutex "
          "some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "read-lock-of-write-locked-mutex");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanBadReadUnlock) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: read unlock of a write locked mutex "
          "some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "read-unlock-of-write-locked-mutex");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanErrnoInSignal) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: signal handler spoils errno "
          "some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "signal-handler-spoils-errno");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanSignalUnsafe) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: signal-unsafe call inside of a signal "
          "some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "signal-unsafe-call-inside-of-a-signal");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanSwiftAccessRace) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: Swift access race some/file.cc:12:34 in "
          "Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "data-race");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanThreadLeak) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: thread leak some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "thread-leak");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanBadUnlock) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: unlock of an unlocked mutex (or by a "
          "wrong thread) some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "unlock-unlocked-mutex");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanInvalidMutex) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: use of an invalid mutex (e.g. "
          "uninitialized or destroyed) some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "use-invalid-mutex");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanHeapUseAfterFree) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: heap-use-after-free some/file.cc:12:34 "
          "in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "heap-use-after-free");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest,
     ExtractsCrashTypeForTSanFallbackSingleToken) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: ThreadSanitizer: unknown-crash-type some/file.cc:12:34 "
          "in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "unknown-crash-type");
}

TEST(ParseCrashTypeFromSanitizerSummaryTest, IgnoresTsanCrashTypeForNonTSan) {
  const absl::StatusOr<std::string> crash_type =
      ParseCrashTypeFromSanitizerSummary(
          "SUMMARY: AddressSanitizer: data race some/file.cc:12:34 in Foo");
  ASSERT_TRUE(crash_type.ok());
  EXPECT_EQ(*crash_type, "data");
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
