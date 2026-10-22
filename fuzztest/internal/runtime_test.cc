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

#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>

#include "gtest/gtest.h"
#include "absl/base/attributes.h"
#include "absl/base/optimization.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "./fuzztest/domain_core.h"
#include "./fuzztest/internal/configuration.h"
#include "./fuzztest/internal/test_protobuf.pb.h"

namespace test_app {

ABSL_ATTRIBUTE_NOINLINE void LeafSanitizerCrash(
    fuzztest::internal::Runtime& runtime, absl::string_view crash_type) {
  runtime.OnSanitizerErrorSummary(crash_type);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
}

ABSL_ATTRIBUTE_NOINLINE void CallerSanitizerCrash(
    fuzztest::internal::Runtime& runtime, absl::string_view crash_type) {
  LeafSanitizerCrash(runtime, crash_type);
  ABSL_BLOCK_TAIL_CALL_OPTIMIZATION();
}

}  // namespace test_app

namespace fuzztest::internal {
namespace {

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

TEST(OnFailureTest, CrashMetadataListenerReceivesDescriptionAndSignature) {
  auto& runtime = Runtime::instance();
  auto received = std::make_shared<std::pair<std::string, std::string>>();
  runtime.RegisterCrashMetadataListener(
      [received](absl::string_view description, absl::string_view signature) {
        *received = {std::string(description), std::string(signature)};
      });

  FuzzTest test({"SUITE_NAME", "TEST_NAME", "FILE", 123}, nullptr);
  Configuration configuration;
  std::tuple args(17);
  const RuntimeStats stats = {absl::FromUnixNanos(0), 1, 2, 3, 4, 5};
  runtime.EnableReporter(&stats, [] { return absl::FromUnixNanos(1979); });
  runtime.SetRunMode(RunMode::kFuzz);
  UntypedDomain domain = TupleOf(Arbitrary<int>());
  GenericDomainCorpusType generic_args(std::in_place_type<std::tuple<int>>,
                                       args);
  Runtime::Args debug_args{generic_args, domain};
  runtime.SetCurrentTest(&test, &configuration);
  runtime.SetCurrentArgs(&debug_args);

  const auto trigger_report = [&] {
    std::string unused;
    runtime.PrintReport(&unused);
  };

  // Both crash_type_ and crash_signature_ are unset.
  EXPECT_EQ(runtime.crash_type(), std::nullopt);
  trigger_report();
  EXPECT_EQ(received->first, "Generic crash");
  EXPECT_EQ(received->second, "Generic crash");

  // crash_type_ is set, crash_signature_ is unset (defaults to crash_type_).
  runtime.SetCrashTypeIfUnset("SIGSEGV");
  runtime.SetCrashTypeIfUnset("ignored");
  EXPECT_EQ(runtime.crash_type(), "SIGSEGV");
  trigger_report();
  EXPECT_EQ(received->first,
            "SIGSEGV\nCRASH_TYPE=SIGSEGV\nCRASH_SIGNATURE=SIGSEGV");
  EXPECT_EQ(received->second, "SIGSEGV");

  // crash_signature_ is explicitly set.
  runtime.SetCrashSignatureIfUnset("SIGSEGV Foo bar.cc:10:5");
  runtime.SetCrashSignatureIfUnset("ignored");
  trigger_report();
  EXPECT_EQ(received->first,
            "SIGSEGV\nCRASH_TYPE=SIGSEGV\n"
            "CRASH_SIGNATURE=SIGSEGV Foo bar.cc:10:5");
  EXPECT_EQ(received->second, "SIGSEGV Foo bar.cc:10:5");

  // Setup failure (current_args_ == nullptr) prefixes both description and
  // signature.
  runtime.UnsetCurrentArgs();
  trigger_report();
  EXPECT_EQ(received->first,
            "SETUP FAILURE: SIGSEGV\nCRASH_TYPE=SIGSEGV\n"
            "CRASH_SIGNATURE=SIGSEGV Foo bar.cc:10:5");
  EXPECT_EQ(received->second, "SETUP FAILURE: SIGSEGV Foo bar.cc:10:5");

  // ResetCrashType() resets both crash_type_ and crash_signature_.
  runtime.SetCurrentArgs(&debug_args);
  runtime.ResetCrashType();
  EXPECT_EQ(runtime.crash_type(), std::nullopt);
  trigger_report();
  EXPECT_EQ(received->first, "Generic crash");
  EXPECT_EQ(received->second, "Generic crash");

  // OnSanitizerErrorSummary sets crash_type_ and formats crash_signature_ with
  // the top application stack frames.
  test_app::CallerSanitizerCrash(runtime, "heap-use-after-free");
  test_app::CallerSanitizerCrash(runtime, "ignored");
  EXPECT_EQ(runtime.crash_type(), "heap-use-after-free");
  trigger_report();
  EXPECT_TRUE(
      absl::StartsWith(received->second,
                       "heap-use-after-free:test_app::LeafSanitizerCrash/"
                       "test_app::CallerSanitizerCrash"))
      << "Actual signature: " << received->second;
  EXPECT_EQ(received->first,
            absl::StrCat("heap-use-after-free\nCRASH_TYPE=heap-use-after-free\n"
                         "CRASH_SIGNATURE=",
                         received->second));

  runtime.UnsetCurrentArgs();
  runtime.DisableReporter();
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
