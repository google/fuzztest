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

#include <sys/mman.h>
#include <unistd.h>

#include <csignal>
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

// Emulates targets (e.g., V8's Wasm trap handler) that install their own
// SIGSEGV/SIGBUS handler before FuzzTest does and recover from faults they
// expect. The handler only recovers from faults on `guard_page`, by making the
// page accessible so that the faulting access is retried and succeeds. Any
// other fault falls back to the default action. Both signals are handled
// because some platforms (e.g., macOS) may deliver this fault as SIGBUS.
void* guard_page = nullptr;

void RecoveringFaultHandler(int signum, siginfo_t* info, void*) {
  if (info->si_addr == guard_page &&
      mprotect(guard_page, getpagesize(), PROT_READ | PROT_WRITE) == 0) {
    constexpr char kMsg[] = "<<Recovered from expected fault>>\n";
    write(STDERR_FILENO, kMsg, sizeof(kMsg) - 1);
    return;  // The faulting access is retried and now succeeds.
  }
  signal(signum, SIG_DFL);  // Retrying the access now crashes.
}

// Installs `RecoveringFaultHandler` if INSTALL_RECOVERING_FAULT_HANDLER is set.
// Global environments are set up before any test runs, and therefore before
// FuzzTest installs its own signal handlers.
class RecoveringFaultHandlerEnvironment : public testing::Environment {
 public:
  void SetUp() override {
    if (std::getenv("INSTALL_RECOVERING_FAULT_HANDLER") == nullptr) {
      return;
    }
    guard_page = mmap(nullptr, getpagesize(), PROT_NONE,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (guard_page == MAP_FAILED) {
      perror("mmap");
      std::abort();
    }
    struct sigaction action = {};
    sigemptyset(&action.sa_mask);
    action.sa_sigaction = RecoveringFaultHandler;
    action.sa_flags = SA_SIGINFO;
    if (sigaction(SIGSEGV, &action, nullptr) != 0 ||
        sigaction(SIGBUS, &action, nullptr) != 0) {
      perror("sigaction");
      std::abort();
    }
  }
};

testing::Environment* const recovering_fault_handler_environment =
    testing::AddGlobalTestEnvironment(new RecoveringFaultHandlerEnvironment);

// Writes to `guard_page`, which faults on the first run only and is recovered
// by `RecoveringFaultHandler`. Does nothing if the handler is not installed.
void RecoversFromExpectedFault(int) {
  if (guard_page == nullptr) {
    return;
  }
  *static_cast<volatile char*>(guard_page) = 1;
}
FUZZ_TEST(MySuite, RecoversFromExpectedFault);

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
    if (!first_iteration_) {
      fprintf(stderr,
              "Request to skip SkippedTestFixturePerIteration.SkippedTest\n");
      fuzztest::SkipTestsOrCurrentInput();
    }
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
