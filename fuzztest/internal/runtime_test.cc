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

#include "./fuzztest/internal/runtime.h"

#if defined(__linux__)
#include <signal.h>
#include <sys/syscall.h>
#include <unistd.h>
#endif

#include <cstdlib>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include "gtest/gtest.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzztest/domain_core.h"
#include "./fuzztest/internal/configuration.h"
#include "./fuzztest/internal/test_protobuf.pb.h"

namespace fuzztest::internal {
namespace {

#if defined(__linux__)
TEST(HandleCrashTest, NonCrashingSigtrapDoesNotSetCrashType) {
  if (IsSignalHandlerDisabled("SIGTRAP")) {
    GTEST_SKIP() << "SIGTRAP handler is disabled";
  }
  const auto test_body = [] {
    static int old_sigtrap_count = 0;
    old_sigtrap_count = 0;
    struct sigaction old_sigtrap = {};
    old_sigtrap.sa_sigaction = [](int, siginfo_t*, void*) {
      ++old_sigtrap_count;
    };
    old_sigtrap.sa_flags = SA_SIGINFO;
    struct sigaction previous_sigtrap = {};
    ASSERT_EQ(sigaction(SIGTRAP, &old_sigtrap, &previous_sigtrap), 0);

    auto& runtime = Runtime::instance();
    FuzzTest test({"SUITE_NAME", "TEST_NAME", "FILE", 123}, nullptr);
    Configuration configuration;
    std::tuple args(17, std::string("ABC"));
    const RuntimeStats stats = {absl::FromUnixNanos(0), 1, 2, 3, 4, 5};
    UntypedDomain domain = TupleOf(Arbitrary<int>(), Arbitrary<std::string>());
    GenericDomainCorpusType generic_args(
        std::in_place_type<std::tuple<int, std::string>>, args);
    Runtime::Args debug_args{generic_args, domain};
    runtime.SetRunMode(RunMode::kFuzz);
    runtime.SetCurrentTest(&test, &configuration);
    runtime.SetCurrentArgs(&debug_args);
    runtime.EnableReporter(&stats, [] { return absl::FromUnixNanos(1979); });

    struct sigaction current_sigtrap = {};
    ASSERT_EQ(sigaction(SIGTRAP, nullptr, &current_sigtrap), 0);
    ASSERT_NE(current_sigtrap.sa_sigaction, old_sigtrap.sa_sigaction);

    siginfo_t sigtrap_info = {};
    sigtrap_info.si_signo = SIGTRAP;
    sigtrap_info.si_code = SI_TIMER;
    ASSERT_EQ(syscall(SYS_rt_tgsigqueueinfo, getpid(), syscall(SYS_gettid),
                      SIGTRAP, &sigtrap_info),
              0);
    EXPECT_EQ(old_sigtrap_count, 1);

    runtime.SetCrashTypeIfUnset("Custom crash type");
    auto seen_crash_type = std::make_shared<std::string>();
    runtime.RegisterCrashMetadataListener(
        [seen_crash_type](absl::string_view crash_type,
                          absl::Span<const std::string>) {
          *seen_crash_type = std::string(crash_type);
        });
    std::string report;
    runtime.PrintReport(&report);
    EXPECT_EQ(*seen_crash_type, "Custom crash type");

    runtime.DisableReporter();
    runtime.ResetCrashType();
    runtime.UnsetCurrentArgs();
    runtime.SetCurrentTest(nullptr, nullptr);
    runtime.SetRunMode(RunMode::kUnitTest);
    ASSERT_EQ(sigaction(SIGTRAP, &previous_sigtrap, nullptr), 0);
  };

  const std::string previous_death_test_style =
      GTEST_FLAG_GET(death_test_style);
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  EXPECT_EXIT(
      {
        testing::UnitTest::GetInstance()->listeners().SuppressEventForwarding(
            false);
        test_body();
        std::_Exit(testing::Test::HasFailure() ? 1 : 0);
      },
      ::testing::ExitedWithCode(0), "");
  GTEST_FLAG_SET(death_test_style, previous_death_test_style);
}
#endif

TEST(OnFailureTest, Output) {
  auto& runtime = Runtime::instance();
  const auto get_failure = [&] {
    std::string s;
    runtime.PrintReport(&s);
    return s;
  };
  // Disabled by default.
  EXPECT_EQ(get_failure(), "");

  FuzzTest test({"SUITE_NAME", "TEST_NAME", "FILE", 123}, nullptr);
  Configuration configuration;
  std::tuple args(17, std::string("ABC"));
  const RuntimeStats stats = {absl::FromUnixNanos(0), 1, 2, 3, 4, 5};
  runtime.EnableReporter(&stats, [] { return absl::FromUnixNanos(1979); });
  runtime.SetRunMode(RunMode::kFuzz);
  UntypedDomain domain = TupleOf(Arbitrary<int>(), Arbitrary<std::string>());
  GenericDomainCorpusType generic_args(
      std::in_place_type<std::tuple<int, std::string>>, args);
  Runtime::Args debug_args{generic_args, domain};
  runtime.SetCurrentTest(&test, &configuration);
  runtime.SetCurrentArgs(&debug_args);
  const std::string report = get_failure();

  EXPECT_TRUE(absl::StartsWith(report, R"(
=================================================================
=== Fuzzing stats

Elapsed time: 1.979us
Total runs: 1
Edges covered: 2
Total edges: 3
Corpus size: 4
Max stack used: 5

=================================================================
=== BUG FOUND!

FILE:123: Counterexample found for SUITE_NAME.TEST_NAME.
The test fails with input:
argument 0: 17
argument 1: "ABC"
)"));

  EXPECT_TRUE(absl::StrContains(report, R"(
=================================================================
=== Regression test draft

TEST(SUITE_NAME, TEST_NAMERegression) {
  TEST_NAME(
    17,
    "ABC"
  );
}

Please note that the code generated above is best effort and is intended
to be used as a draft regression test.
For reproducing findings please rely on file based reproduction.

=================================================================
)"));

  runtime.DisableReporter();
  EXPECT_EQ(get_failure(), "");
}

TEST(OnFailureTest, DisablesReporterAfterPrintingReportOnce) {
  auto& runtime = Runtime::instance();
  const auto get_failure = [&] {
    std::string s;
    runtime.PrintReport(&s);
    return s;
  };

  FuzzTest test({"SUITE_NAME", "TEST_NAME", "FILE", 123}, nullptr);
  Configuration configuration;
  std::tuple args(17, std::string("ABC"));
  const RuntimeStats stats = {absl::FromUnixNanos(0), 1, 2, 3, 4, 5};
  UntypedDomain domain = TupleOf(Arbitrary<int>(), Arbitrary<std::string>());
  GenericDomainCorpusType generic_args(
      std::in_place_type<std::tuple<int, std::string>>, args);
  Runtime::Args debug_args{generic_args, domain};
  runtime.SetRunMode(RunMode::kFuzz);
  runtime.SetCurrentTest(&test, &configuration);
  runtime.SetCurrentArgs(&debug_args);
  runtime.EnableReporter(&stats, [] { return absl::FromUnixNanos(1979); });

  auto crash_metadata_listener_calls = std::make_shared<int>(0);
  runtime.RegisterCrashMetadataListener(
      [crash_metadata_listener_calls](absl::string_view,
                                      absl::Span<const std::string>) {
        ++*crash_metadata_listener_calls;
      });

  EXPECT_NE(get_failure(), "");
  EXPECT_EQ(*crash_metadata_listener_calls, 1);

  // Once a report is printed, subsequent PrintReport calls in the same
  // EnableReporter session must not emit a duplicate report.
  EXPECT_EQ(get_failure(), "");
  EXPECT_EQ(*crash_metadata_listener_calls, 1);

  // Re-enabling the reporter allows printing again, once.
  runtime.EnableReporter(&stats, [] { return absl::FromUnixNanos(1979); });
  EXPECT_NE(get_failure(), "");
  EXPECT_EQ(*crash_metadata_listener_calls, 2);
  EXPECT_EQ(get_failure(), "");
  EXPECT_EQ(*crash_metadata_listener_calls, 2);

  runtime.UnsetCurrentArgs();
  runtime.SetCurrentTest(nullptr, nullptr);
  runtime.SetRunMode(RunMode::kUnitTest);
}

TEST(RegressionTestNameForCrashingInputTest,
     ReturnsRegressionTestNameForValidInputFilename) {
  const absl::StatusOr<std::string> regression_test_name =
      RegressionTestNameForCrashingInput("MySuite.MyTest",
                                         "/path/to/bug_id-crash_sig-input_sig");
  ASSERT_TRUE(regression_test_name.ok());
  EXPECT_EQ(*regression_test_name, "MySuite.MyTest/Regression/bug_id");
}

TEST(RegressionTestNameForCrashingInputTest,
     ReturnsErrorForInvalidInputFilename) {
  const absl::StatusOr<std::string> regression_test_name =
      RegressionTestNameForCrashingInput("MySuite.MyTest",
                                         "single_dash-is_invalid");
  EXPECT_FALSE(regression_test_name.ok());
}

}  // namespace
}  // namespace fuzztest::internal
