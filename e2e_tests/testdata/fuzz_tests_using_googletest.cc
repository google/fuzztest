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

// Example fuzz tests that require GoogleTest, for functional testing.
//
// Used by `functional_test` only. We separate these into a different .cc file
// to show that regular FUZZ_TEST work without having to #include GoogleTest.

#include <cstdio>
#include <cstdlib>

#include "gtest/gtest.h"
#include "./fuzztest/fuzztest.h"
#include "absl/strings/match.h"
#include "./fuzztest/googletest_fixture_adapter.h"
#include "./fuzztest/internal/test_protobuf.pb.h"

namespace {

class GlobalEnvironment : public testing::Environment {
 public:
  GlobalEnvironment() {
    fprintf(stderr, "<<GlobalEnvironment::GlobalEnvironment()>>\n");
  }
  ~GlobalEnvironment() override {
    fprintf(stderr, "<<GlobalEnvironment::~GlobalEnvironment()>>\n");
  }
  void SetUp() override { fprintf(stderr, "<<GlobalEnvironment::SetUp()>>\n"); }
  void TearDown() override {
    fprintf(stderr, "<<GlobalEnvironment::TearDown()>>\n");
  }
};

testing::Environment* const global_environment =
    testing::AddGlobalTestEnvironment(new GlobalEnvironment);

void GoogleTestExpect(int a) {
  // Make sure this will fail.
  EXPECT_EQ(a, 42);
}
FUZZ_TEST(MySuite, GoogleTestExpect);

void GoogleTestAssert(int a) {
  // Make sure this will fail.
  ASSERT_EQ(a, 42);
}
FUZZ_TEST(MySuite, GoogleTestAssert);

void GoogleTestNeverFails(int) {}
FUZZ_TEST(MySuite, GoogleTestNeverFails);

void GoogleTestHasCurrentTestInfo(int) {
  EXPECT_TRUE(testing::UnitTest::GetInstance()->current_test_info() != nullptr);
}
FUZZ_TEST(MySuite, GoogleTestHasCurrentTestInfo);

class CallCountGoogleTest : public testing::Test {
 protected:
  static void SetUpTestSuite() {
    fprintf(stderr, "<<CallCountGoogleTest::SetUpTestSuite()>>\n");
  }

  static void TearDownTestSuite() {
    fprintf(stderr, "<<CallCountGoogleTest::TearDownTestSuite()>>\n");
  }

  unsigned int call_count_ = 0;
};

class CallCountPerIteration
    : public ::fuzztest::PerIterationFixtureAdapter<CallCountGoogleTest> {
 public:
  void CallCountIsAlwaysIncrementedFromInitialValue(int) {
    EXPECT_EQ(call_count_++, 0);
  }
};
FUZZ_TEST_F(CallCountPerIteration,
            CallCountIsAlwaysIncrementedFromInitialValue);

static unsigned int global_call_count = 0;
class CallCountPerFuzzTest
    : public ::fuzztest::PerFuzzTestFixtureAdapter<CallCountGoogleTest> {
 public:
  void CallCountPerFuzzTestEqualsToGlobalCount(int) {
    ++call_count_;
    ++global_call_count;
    EXPECT_EQ(call_count_, global_call_count);
  }
  void NeverFails(int) {}
};
FUZZ_TEST_F(CallCountPerFuzzTest, CallCountPerFuzzTestEqualsToGlobalCount);
FUZZ_TEST_F(CallCountPerFuzzTest, NeverFails);

TEST(SharedSuite, WorksAsUnitTest) {}

void WorksAsFuzzTest(int) {}
FUZZ_TEST(SharedSuite, WorksAsFuzzTest);

void NonFatalFailureAllowsMinimization(const std::string& str) {
  // Make very fuzz predicate that would fail on a large number of values, but
  // there is one very specific minimum.
  if (str.size() < 4 || str[0] < '0' || str[1] < '1' || str[2] < '2' ||
      str[3] <= str[2]) {
    return;
  }
  ADD_FAILURE() << str;
}
FUZZ_TEST(MySuite, NonFatalFailureAllowsMinimization);

void CrashOnFailingTestInput(const std::string& input) {
  EXPECT_FALSE(absl::StartsWith(input, "crashing"));
}
FUZZ_TEST(MySuite, CrashOnFailingTestInput);

class SkippedTestFixturePerTest
    : public ::fuzztest::PerFuzzTestFixtureAdapter<testing::Test> {
 public:
  SkippedTestFixturePerTest() { fuzztest::SkipTestsOrCurrentInput(); }

  void SkippedTest() {
    fprintf(stderr, "SkippedTest is executed! Aborting\n");
    std::abort();
  }
};
FUZZ_TEST_F(SkippedTestFixturePerTest, SkippedTest);

class SkippedTestFixturePerIteration
    : public ::fuzztest::PerIterationFixtureAdapter<testing::Test> {
 public:
  // For the engine limitation, there must be at least one non-skipped input
  // when initializing the corpus for fuzzing. So we always accept the first
  // input.
  SkippedTestFixturePerIteration() {
    if (!first_iteration_) fuzztest::SkipTestsOrCurrentInput();
  }

  void SkippedTest() {
    if (first_iteration_) {
      first_iteration_ = false;
      return;
    }
    fprintf(stderr, "SkippedTest is executed! Aborting\n");
    std::abort();
  }

 private:
  static bool first_iteration_;
};
bool SkippedTestFixturePerIteration::first_iteration_ = true;
FUZZ_TEST_F(SkippedTestFixturePerIteration, SkippedTest);

}  // namespace
