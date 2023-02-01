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

#include <utility>

#include "gtest/gtest.h"
#include "./fuzztest/internal/registry.h"
#include "./fuzztest/internal/runtime.h"

#define GOOGLEFUZZTEST_REGISTER_FOR_GOOGLETEST(selected_run_mode, argc, argv) \
  (::fuzztest::internal::ForEachTest([&](const auto& test) {                  \
     auto fixture_factory =                                                   \
         [argc, argv, &test]() -> ::fuzztest::internal::GTest_TestAdaptor* {  \
       return new ::fuzztest::internal::GTest_TestAdaptor(test, argc, argv);  \
     };                                                                       \
     auto test_factory = [argc, argv, &test]() -> ::testing::Test* {          \
       return new ::fuzztest::internal::GTest_TestAdaptor(test, argc, argv);  \
     };                                                                       \
     if (test.uses_fixture()) {                                               \
       ::testing::RegisterTest(test.suite_name(), test.test_name(), nullptr,  \
                               nullptr, test.file(), test.line(),             \
                               std::move(fixture_factory));                   \
     } else {                                                                 \
       ::testing::RegisterTest(test.suite_name(), test.test_name(), nullptr,  \
                               nullptr, test.file(), test.line(),             \
                               std::move(test_factory));                      \
     }                                                                        \
   }),                                                                        \
   ::testing::UnitTest::GetInstance()->listeners().Append(                    \
       new ::fuzztest::internal::GTest_EventListener<                         \
           ::testing::EmptyTestEventListener, ::testing::TestPartResult>()),  \
   ::fuzztest::internal::Runtime::instance().SetRunMode(selected_run_mode))

namespace fuzztest::internal {

class GTest_TestAdaptor : public ::testing::Test {
 public:
  explicit GTest_TestAdaptor(const FuzzTest& test, int* argc, char*** argv)
      : test_(test), argc_(argc), argv_(argv) {}

  void TestBody() override {
    auto test = test_.make();
    if (Runtime::instance().run_mode() == RunMode::kUnitTest) {
      test->RunInUnitTestMode();
    } else {
      ASSERT_EQ(0, test->RunInFuzzingMode(argc_, argv_)) << "Fuzzing failure.";
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
  const FuzzTest& test_;
  int* argc_;
  char*** argv_;
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

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_GOOGLETEST_ADAPTOR_H_
