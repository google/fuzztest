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

#ifndef FUZZTEST_FUZZTEST_GOOGLETEST_ADAPTOR_H_
#define FUZZTEST_FUZZTEST_GOOGLETEST_ADAPTOR_H_

#include <algorithm>
#include <cstdlib>

#include "gtest/gtest.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/internal/configuration.h"
#include "./fuzztest/internal/registry.h"
#include "./fuzztest/internal/runtime.h"

namespace fuzztest::internal {

class GTest_TestAdaptor : public ::testing::Test {
 public:
  explicit GTest_TestAdaptor(FuzzTest& test, int* argc, char*** argv,
                             Configuration configuration)
      : test_(test),
        argc_(argc),
        argv_(argv),
        configuration_(std::move(configuration)) {}

  void TestBody() override {
    auto test = test_.make();
    if (Runtime::instance().run_mode() == RunMode::kUnitTest) {
      if (configuration_.crashing_input_to_reproduce.has_value()) {
#ifdef GTEST_HAS_DEATH_TEST
        // `RunInUnitTestMode` is supposed to fail and we wish to show the
        // failure to the user. Directly running the test would terminate the
        // process and using `EXPECT_DEATH` causes the test to pass. We use
        // `EXPECT_EXIT` so that the test exit unsuccessfully, meaning that the
        // test below fails without terminating the process.
        EXPECT_EXIT((test->RunInUnitTestMode(configuration_), std::exit(0)),
                    ::testing::ExitedWithCode(0), "");
#else
        test->RunInUnitTestMode(configuration_);
#endif
      } else {
        test->RunInUnitTestMode(configuration_);
      }
    } else {
      // TODO(b/245753736): Consider using `tolerate_failure` when FuzzTest can
      // tolerate crashes in fuzzing mode.
      ASSERT_EQ(0, test->RunInFuzzingMode(argc_, argv_, configuration_))
          << "Fuzzing failure.";
    }
  }

  static void SetUpTestSuite() {
    SetUpTearDownTestSuiteFunction set_up_test_suite = GetSetUpTestSuite(
        testing::UnitTest::GetInstance()->current_test_suite()->name());
    if (set_up_test_suite != nullptr) set_up_test_suite();
  }

  static void TearDownTestSuite() {
    SetUpTearDownTestSuiteFunction tear_down_test_suite = GetTearDownTestSuite(
        testing::UnitTest::GetInstance()->current_test_suite()->name());
    if (tear_down_test_suite != nullptr) tear_down_test_suite();
  }

 private:
  FuzzTest& test_;
  int* argc_;
  char*** argv_;
  Configuration configuration_;
};

template <typename Base, typename TestPartResult>
class GTest_EventListener : public Base {
 public:
  void OnTestPartResult(const TestPartResult& test_part_result) override {
    if (!test_part_result.failed()) return;
    Runtime& runtime = Runtime::instance();
    if (runtime.run_mode() == RunMode::kFuzz) {
      if (runtime.should_terminate_on_non_fatal_failure()) {
        // The SIGABRT will trigger a report.
        std::abort();
      }
    } else {
      // Otherwise, we report it manually.
      runtime.PrintReportOnDefaultSink();
    }
    runtime.SetExternalFailureDetected(true);
  }
};

// Registers FUZZ_TEST as GoogleTest TEST-s.
void RegisterFuzzTestsAsGoogleTests(int* argc, char*** argv,
                                    const Configuration& configuration);

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_GOOGLETEST_ADAPTOR_H_
