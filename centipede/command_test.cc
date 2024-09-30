// Copyright 2022 The Centipede Authors.
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

#include "./centipede/command.h"

#include <signal.h>
#include <sys/wait.h>  // NOLINT(for WTERMSIG)

#include <cstdlib>
#include <filesystem>  // NOLINT
#include <string>
#include <string_view>

#include "gtest/gtest.h"
#include "absl/log/log.h"
#include "absl/strings/substitute.h"
#include "absl/time/time.h"
#include "./centipede/early_exit.h"
#include "./centipede/util.h"
#include "./common/test_util.h"

namespace centipede {
namespace {

TEST(CommandTest, ToString) {
  EXPECT_EQ(Command("x").ToString(), "x");
  EXPECT_EQ(Command("path", {"arg1", "arg2"}).ToString(),
            "path \\\narg1 \\\narg2");
  EXPECT_EQ(Command("x", {}, {"K1=V1", "K2=V2"}).ToString(),
            "K1=V1 \\\nK2=V2 \\\nx");
  EXPECT_EQ(Command("x", {}, {}, "out").ToString(), "x \\\n> out");
  EXPECT_EQ(Command("x", {}, {}, "", "err").ToString(), "x \\\n2> err");
  EXPECT_EQ(Command("x", {}, {}, "out", "err").ToString(),
            "x \\\n> out \\\n2> err");
  EXPECT_EQ(Command("x", {}, {}, "out", "out").ToString(),
            "x \\\n> out \\\n2>&1");
}

TEST(CommandTest, Execute) {
  // Check for default exit code.
  Command echo("echo");
  EXPECT_EQ(echo.Execute(), 0);
  EXPECT_FALSE(EarlyExitRequested());

  // Check for exit code 7.
  Command exit7("bash -c 'exit 7'");
  EXPECT_EQ(exit7.Execute(), 7);
  EXPECT_FALSE(EarlyExitRequested());
}

TEST(CommandDeathTest, Execute) {
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  // Test for interrupt handling.
  const auto self_sigint_lambda = []() {
    Command self_sigint("bash -c 'kill -SIGINT $$'");
    self_sigint.Execute();
    if (EarlyExitRequested()) {
      LOG(INFO) << "Early exit requested";
      exit(ExitCode());
    }
  };
  EXPECT_DEATH(self_sigint_lambda(), "Early exit requested");
}

TEST(CommandTest, InputFileWildCard) {
  std::string_view command_line = "foo bar @@ baz";
  Command cmd(command_line, {}, {}, "", "", absl::Seconds(2), "TEMP_FILE");
  EXPECT_EQ(cmd.ToString(), "foo bar TEMP_FILE baz");
}

TEST(CommandTest, ForkServer) {
  const std::string test_tmpdir = GetTestTempDir(test_info_->name());
  const std::string helper =
      GetDataDependencyFilepath("centipede/command_test_helper");

  // TODO(ussuri): Dedupe these testcases.

  {
    const std::string input = "success";
    const std::string log = std::filesystem::path{test_tmpdir} / input;
    Command cmd(helper, {input}, {}, log, log);
    EXPECT_TRUE(cmd.StartForkServer(test_tmpdir, "ForkServer"));
    EXPECT_EQ(cmd.Execute(), EXIT_SUCCESS);
    std::string log_contents;
    ReadFromLocalFile(log, log_contents);
    EXPECT_EQ(log_contents, absl::Substitute("Got input: $0", input));
  }

  {
    const std::string input = "fail";
    const std::string log = std::filesystem::path{test_tmpdir} / input;
    Command cmd(helper, {input}, {}, log, log);
    EXPECT_TRUE(cmd.StartForkServer(test_tmpdir, "ForkServer"));
    EXPECT_EQ(cmd.Execute(), EXIT_FAILURE);
    std::string log_contents;
    ReadFromLocalFile(log, log_contents);
    EXPECT_EQ(log_contents, absl::Substitute("Got input: $0", input));
  }

  {
    const std::string input = "ret42";
    const std::string log = std::filesystem::path{test_tmpdir} / input;
    Command cmd(helper, {input}, {}, log, log);
    EXPECT_TRUE(cmd.StartForkServer(test_tmpdir, "ForkServer"));
    EXPECT_EQ(cmd.Execute(), 42);
    std::string log_contents;
    ReadFromLocalFile(log, log_contents);
    EXPECT_EQ(log_contents, absl::Substitute("Got input: $0", input));
  }

  {
    const std::string input = "abort";
    const std::string log = std::filesystem::path{test_tmpdir} / input;
    Command cmd(helper, {input}, {}, log, log);
    EXPECT_TRUE(cmd.StartForkServer(test_tmpdir, "ForkServer"));
    // WTERMSIG() needs an lvalue on some platforms.
    const int ret = cmd.Execute();
    EXPECT_EQ(WTERMSIG(ret), SIGABRT);
    std::string log_contents;
    ReadFromLocalFile(log, log_contents);
    EXPECT_EQ(log_contents, absl::Substitute("Got input: $0", input));
  }

  {
    const std::string input = "hang";
    const std::string log = std::filesystem::path{test_tmpdir} / input;
    constexpr auto kTimeout = absl::Seconds(2);
    Command cmd(helper, {input}, {}, log, log, kTimeout);
    ASSERT_TRUE(cmd.StartForkServer(test_tmpdir, "ForkServer"));
    EXPECT_EQ(cmd.Execute(), EXIT_FAILURE);
    std::string log_contents;
    ReadFromLocalFile(log, log_contents);
    EXPECT_EQ(log_contents, absl::Substitute("Got input: $0", input));
  }

  // TODO(kcc): [impl] test what happens if the child is interrupted.
}

}  // namespace
}  // namespace centipede
