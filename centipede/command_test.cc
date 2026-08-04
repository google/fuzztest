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
#if !defined(_WIN32)
#include <sys/wait.h>  // NOLINT(for WTERMSIG)
#endif

#include <cstdlib>
#include <filesystem>  // NOLINT
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/substitute.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./centipede/stop.h"
#include "./centipede/util.h"
#include "./common/test_util.h"

#if defined(_WIN32)
#define setenv(n, v, _r) _putenv_s(n, v)
#endif

namespace fuzztest::internal {
namespace {

using ::testing::AllOf;
using ::testing::HasSubstr;
using ::testing::Optional;

TEST(CommandTest, Execute) {
  const std::string helper =
      GetDataDependencyFilepath("centipede/command_test_helper").string();
  StopCondition stop_condition;

  // Check for default exit code.
  Command::Options options_success;
  options_success.args = {"success"};
  Command success_cmd{helper, std::move(options_success)};
  EXPECT_EQ(success_cmd.Execute(&stop_condition), 0);
  EXPECT_FALSE(stop_condition.ShouldStop());

  // Check for exit code 7.
  Command::Options options_ret7;
  options_ret7.args = {"ret7"};
  Command exit7{helper, std::move(options_ret7)};
  EXPECT_EQ(exit7.Execute(&stop_condition), 7);
  EXPECT_FALSE(stop_condition.ShouldStop());
}

TEST(CommandTest, HandlesInterruptedCommand) {
  const std::string helper =
      GetDataDependencyFilepath("centipede/command_test_helper").string();
  StopCondition stop_condition;
  Command::Options options_ctrlc;
  options_ctrlc.args = {"ctrlc"};
  Command self_ctrlc{helper, std::move(options_ctrlc)};
  // Cannot set to SIG_IGN as the command would inherit that.
  signal(SIGINT, [](int) {});
  self_ctrlc.ExecuteAsync();
  signal(SIGINT, SIG_DFL);
  self_ctrlc.Wait(absl::InfiniteFuture(), &stop_condition);
  EXPECT_TRUE(stop_condition.ShouldStop());
}

TEST(CommandTest, ExecuteWithOptions) {
  const std::filesystem::path test_tmpdir = GetTestTempDir(test_info_->name());
  const std::string helper =
      GetDataDependencyFilepath("centipede/command_test_helper").string();

  {
    const std::string log_prefix = (test_tmpdir / "args").string();
    Command::Options cmd_options;
    cmd_options.args = {"echo_args", "arg1", "arg2"};
    cmd_options.stdout_file_prefix = log_prefix;
    Command cmd{helper, std::move(cmd_options)};
    EXPECT_EQ(cmd.Execute(), 0);
    std::string log_contents;
    ReadFromLocalFile(cmd.stdout_file(), log_contents);
    EXPECT_THAT(log_contents,
                AllOf(HasSubstr("arg[0]=arg1\n"), HasSubstr("arg[1]=arg2\n")));
  }

  {
    setenv("K3", "V3", 1);
    const std::string log_prefix = (test_tmpdir / "env").string();
    Command::Options cmd_options;
    cmd_options.args = {"echo_env", "K1", "K2", "K3"};
    cmd_options.env_diff = {"K1=V1", "K2=V2", "-K3"};
    cmd_options.stdout_file_prefix = log_prefix;
    Command cmd{helper, std::move(cmd_options)};
    EXPECT_EQ(cmd.Execute(), 0);
    std::string log_contents;
    ReadFromLocalFile(cmd.stdout_file(), log_contents);
    EXPECT_THAT(log_contents, AllOf(HasSubstr("K1=V1\n"), HasSubstr("K2=V2\n"),
                                    HasSubstr("K3=<UNSET>\n")));
  }

  {
    const std::string stdin_file = (test_tmpdir / "input.txt").string();
    WriteToLocalFile(stdin_file, "hello stdin");
    const std::string log_prefix = (test_tmpdir / "stdin").string();
    Command::Options cmd_options;
    cmd_options.args = {"echo_stdin"};
    cmd_options.stdin_file_path = stdin_file;
    cmd_options.stdout_file_prefix = log_prefix;
    Command cmd{helper, std::move(cmd_options)};
    EXPECT_EQ(cmd.Execute(), 0);
    std::string log_contents;
    ReadFromLocalFile(cmd.stdout_file(), log_contents);
    EXPECT_THAT(log_contents, HasSubstr("hello stdin"));
  }
}

TEST(CommandTest, InputFileWildCard) {
  const std::filesystem::path test_tmpdir = GetTestTempDir(test_info_->name());
  const std::string helper =
      GetDataDependencyFilepath("centipede/command_test_helper").string();
  const std::string log_prefix = (test_tmpdir / "wildcard").string();

  Command::Options cmd_options;
  cmd_options.temp_file_path = "TEMP_FILE";
  cmd_options.stdout_file_prefix = log_prefix;
  Command cmd{absl::StrCat(helper, " @@"), std::move(cmd_options)};
  EXPECT_EQ(cmd.Execute(), 17);
  std::string log_contents;
  ReadFromLocalFile(cmd.stdout_file(), log_contents);
  EXPECT_EQ(log_contents, "Got input: TEMP_FILE\n");
}

#if !defined(_WIN32)
TEST(CommandTest, ForkServer) {
  const std::filesystem::path test_tmpdir = GetTestTempDir(test_info_->name());
  const std::string helper =
      GetDataDependencyFilepath("centipede/command_test_helper");

  // TODO(ussuri): Dedupe these testcases.

  {
    const std::string input = "success";
    const std::string log_prefix = test_tmpdir / input;
    Command::Options cmd_options;
    cmd_options.args = {input};
    cmd_options.stdout_file_prefix = log_prefix;
    cmd_options.stderr_file_prefix = log_prefix;
    Command cmd{helper, std::move(cmd_options)};
    EXPECT_TRUE(cmd.StartForkServer(test_tmpdir.string(), "ForkServer"));
    EXPECT_EQ(cmd.Execute(), EXIT_SUCCESS);
    std::string log_contents;
    ReadFromLocalFile(cmd.stdout_file(), log_contents);
    EXPECT_EQ(log_contents, absl::Substitute("Got input: $0\n", input));
  }

  {
    const std::string input = "fail";
    const std::string log_prefix = test_tmpdir / input;
    Command::Options cmd_options;
    cmd_options.args = {input};
    cmd_options.stdout_file_prefix = log_prefix;
    cmd_options.stderr_file_prefix = log_prefix;
    Command cmd{helper, std::move(cmd_options)};
    EXPECT_TRUE(cmd.StartForkServer(test_tmpdir.string(), "ForkServer"));
    EXPECT_EQ(cmd.Execute(), EXIT_FAILURE);
    std::string log_contents;
    ReadFromLocalFile(cmd.stdout_file(), log_contents);
    EXPECT_EQ(log_contents, absl::Substitute("Got input: $0\n", input));
  }

  {
    const std::string input = "ret42";
    const std::string log_prefix = test_tmpdir / input;
    Command::Options cmd_options;
    cmd_options.args = {input};
    cmd_options.stdout_file_prefix = log_prefix;
    cmd_options.stderr_file_prefix = log_prefix;
    Command cmd{helper, std::move(cmd_options)};
    EXPECT_TRUE(cmd.StartForkServer(test_tmpdir.string(), "ForkServer"));
    EXPECT_EQ(cmd.Execute(), 42);
    std::string log_contents;
    ReadFromLocalFile(cmd.stdout_file(), log_contents);
    EXPECT_EQ(log_contents, absl::Substitute("Got input: $0\n", input));
  }

  {
    const std::string input = "abort";
    const std::string log_prefix = test_tmpdir / input;
    Command::Options cmd_options;
    cmd_options.args = {input};
    cmd_options.stdout_file_prefix = log_prefix;
    cmd_options.stderr_file_prefix = log_prefix;
    Command cmd{helper, std::move(cmd_options)};
    EXPECT_TRUE(cmd.StartForkServer(test_tmpdir.string(), "ForkServer"));
    // WTERMSIG() needs an lvalue on some platforms.
    const int ret = cmd.Execute();
    EXPECT_EQ(WTERMSIG(ret), SIGABRT);
    std::string log_contents;
    ReadFromLocalFile(cmd.stdout_file(), log_contents);
    EXPECT_EQ(log_contents, absl::Substitute("Got input: $0\n", input));
  }

  {
    const std::string input = "sleep";
    const std::string log_prefix = test_tmpdir / input;
    Command::Options cmd_options;
    cmd_options.args = {input};
    cmd_options.stdout_file_prefix = log_prefix;
    cmd_options.stderr_file_prefix = log_prefix;
    Command cmd{helper, std::move(cmd_options)};
    ASSERT_TRUE(cmd.StartForkServer(test_tmpdir.string(), "ForkServer"));
    ASSERT_TRUE(cmd.ExecuteAsync());
    EXPECT_EQ(cmd.Wait(absl::Now() + absl::Seconds(2)), std::nullopt);
    cmd.RequestStop(/*force=*/false);
    EXPECT_THAT(cmd.Wait(absl::Now() + absl::Seconds(2)), Optional(SIGTERM));
    std::string log_contents;
    ReadFromLocalFile(cmd.stdout_file(), log_contents);
    EXPECT_EQ(log_contents, absl::Substitute("Got input: $0\n", input));
  }

  {
    const std::string input = "hang";
    const std::string log_prefix = test_tmpdir / input;
    Command::Options cmd_options;
    cmd_options.args = {input};
    cmd_options.stdout_file_prefix = log_prefix;
    cmd_options.stderr_file_prefix = log_prefix;
    Command cmd{helper, std::move(cmd_options)};
    ASSERT_TRUE(cmd.StartForkServer(test_tmpdir.string(), "ForkServer"));
    ASSERT_TRUE(cmd.ExecuteAsync());
    EXPECT_EQ(cmd.Wait(absl::Now() + absl::Seconds(2)), std::nullopt);
    cmd.RequestStop(/*force=*/false);
    EXPECT_EQ(cmd.Wait(absl::Now() + absl::Seconds(2)), std::nullopt);
    cmd.RequestStop(/*force=*/true);
    EXPECT_THAT(cmd.Wait(absl::Now() + absl::Seconds(2)), Optional(SIGKILL));
    std::string log_contents;
    ReadFromLocalFile(cmd.stdout_file(), log_contents);
    EXPECT_EQ(log_contents, absl::Substitute("Got input: $0\n", input));
  }

  // TODO(kcc): [impl] test what happens if the child is interrupted.
}
#endif

}  // namespace
}  // namespace fuzztest::internal
