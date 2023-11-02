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

#include "./fuzztest/internal/subprocess.h"

#include <csignal>
#include <sstream>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/functional/function_ref.h"
#include "absl/strings/str_cat.h"
#include "absl/time/time.h"

namespace fuzztest::internal {

void RunExpectExit(absl::FunctionRef<void()> test) { test(); }

namespace {

using ::testing::HasSubstr;

template <typename T>
std::string ToString(T v) {
  std::stringstream ss;
  ss << v;
  return ss.str();
}

TEST(SubProcessTest, ToStringWorks) {
  EXPECT_EQ(ToString(ExitCode(1)), "ExitCode: 1");
  EXPECT_EQ(ToString(Signal(17)), "Signal: 17");
}

TEST(SubProcessTest, StdOutIsCaptured) {
  auto [status, std_out, std_err] = RunCommand({"echo", "hello", "world"});
  EXPECT_TRUE(status.Exited());
  EXPECT_EQ(status, ExitCode(0));
  EXPECT_EQ(ToString(status), "ExitCode: 0");
  EXPECT_EQ(std_out, "hello world\n");
  EXPECT_EQ(std_err, "");
}

TEST(SubProcessTest, StdErrIsCaptured) {
  auto [status, std_out, std_err] = RunCommand({"bash", "-c", "not-a-binary"});
  EXPECT_TRUE(status.Exited());
  EXPECT_NE(status, ExitCode(0));
  EXPECT_EQ(std_out, "");
  EXPECT_THAT(std_err, HasSubstr("command not found"));
}

TEST(SubProcessTest, CrashesWithWrongArguments) {
  EXPECT_DEATH(RunCommand({"not-a-binary"}), "Cannot spawn child process");
}

TEST(SubProcessTest, PassedEnvironmentIsSet) {
  auto [status, std_out, std_err] = RunCommand({"env"}, {{"THING", "42"}});
  EXPECT_TRUE(status.Exited());
  EXPECT_EQ(status, ExitCode(0));
  EXPECT_EQ(std_out, "THING=42\n");
  EXPECT_EQ(std_err, "");
}

TEST(SubProcessTest, TimeoutIsEnforced) {
  auto [status, std_out, std_err] =
      RunCommand({"yes"}, /*environment=*/{}, absl::Seconds(.5));
  EXPECT_TRUE(status.Signaled());
  EXPECT_EQ(status, Signal(SIGTERM));
  EXPECT_EQ(ToString(status), absl::StrCat("Signal: ", SIGTERM));
  EXPECT_GT(std_out.size(), 0);
  EXPECT_EQ(std_err.size(), 0);
}

}  // namespace
}  // namespace fuzztest::internal
