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

#ifndef THIRD_PARTY_CENTIPEDE_COMMAND_H_
#define THIRD_PARTY_CENTIPEDE_COMMAND_H_

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "absl/status/status.h"
#include "absl/time/time.h"

namespace centipede {

class Command final {
 public:
  // Move-constructible only.
  Command(const Command& other) = delete;
  Command& operator=(const Command& other) = delete;
  Command(Command&& other) noexcept;
  Command& operator=(Command&& other) noexcept = delete;

  // Constructs a command:
  // `path`: path to the binary.
  // `args`: arguments.
  // `env`: environment variables/values (in the form "KEY=VALUE").
  // `out`: stdout redirect path (empty means use parent's STDOUT).
  // `err`: stderr redirect path (empty means use parent's STDERR).
  // `timeout`: terminate a fork server execution attempt after this duration.
  // `temp_file_path`: "@@" in `path` will be replaced with `temp_file_path`.
  // If `out` == `err` and both are non-empty, stdout/stderr are combined.
  // TODO(ussuri): The number of parameters became untenable and error-prone.
  //  Use the Options or Builder pattern instead.
  explicit Command(std::string_view path, std::vector<std::string> args = {},
                   std::vector<std::string> env = {}, std::string_view out = "",
                   std::string_view err = "",
                   absl::Duration timeout = absl::InfiniteDuration(),
                   std::string_view temp_file_path = "");

  // Cleans up the fork server, if that was created.
  ~Command();

  // Returns a string representing the command, e.g. like this
  // "ENV1=VAL1 path arg1 arg2 > out 2>& err"
  std::string ToString() const;
  // Executes the command, returns the exit status.
  // Can be called more than once.
  // If interrupted, may call RequestEarlyExit().
  int Execute();

  // Attempts to start a fork server, returns true on success.
  // Pipe files for the fork server are created in `temp_dir_path`
  // with prefix `prefix`.
  // See runner_fork_server.cc for details.
  bool StartForkServer(std::string_view temp_dir_path, std::string_view prefix);

  // Accessors.
  const std::string& path() const { return path_; }

 private:
  struct ForkServerProps;

  // Returns the status of the fork server process. Expects that the server was
  // previously started using `StartForkServer()`.
  absl::Status VerifyForkServerIsHealthy();

  // Reads and returns the stdout of the command, if redirected to a file. If
  // not redirected, returns a placeholder text.
  std::string ReadRedirectedStdout() const;
  // Reads and returns the stderr of the command, if redirected to a file that
  // is also different from the redirected stdout. If not redirected, returns a
  // placeholder text.
  std::string ReadRedirectedStderr() const;
  // Possibly logs information about a crash, starting with `message`, followed
  // by the the command line, followed by the redirected stdout and stderr read
  // from `out_` and `err_` files, if any.
  void LogProblemInfo(std::string_view message) const;
  // Just as `LogCrashInfo()`, but logging occurs only when the VLOG level (set
  // via `--v` or its equivalents) is >= `min_vlog`.
  void VlogProblemInfo(std::string_view message, int vlog_level) const;

  const std::string path_;
  const std::vector<std::string> args_;
  const std::vector<std::string> env_;
  const std::string out_;
  const std::string err_;
  const absl::Duration timeout_;
  const std::string temp_file_path_;
  const std::string command_line_ = ToString();

  std::unique_ptr<ForkServerProps> fork_server_;
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_COMMAND_H_
