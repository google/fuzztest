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

#include <errno.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <csignal>
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <string>
#include <string_view>
#include <system_error>  // NOLINT
#include <utility>
#include <vector>

#include "absl/base/const_init.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/str_split.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./centipede/early_exit.h"
#include "./centipede/util.h"
#include "./common/logging.h"

namespace centipede {

// See the definition of --fork_server flag.
inline constexpr std::string_view kCommandLineSeparator(" \\\n");
inline constexpr std::string_view kNoForkServerRequestPrefix("%f");

// TODO(ussuri): Encapsulate as much of the fork server functionality from
//  this source as possible in this struct, and make it a class.
struct Command::ForkServerProps {
  // The file paths of the comms pipes.
  std::string fifo_path_[2];
  // The file descriptors of the comms pipes.
  int pipe_[2] = {-1, -1};
  // The file path to write the PID of the fork server process to.
  std::string pid_file_path_;
  // The PID of the fork server process. Used to verify that the fork server is
  // running and the pipes are ready for comms.
  pid_t pid_ = -1;
  // A `stat` of the fork server's binary right after it's started. Used to
  // detect that the running process with `pid_` is still the original fork
  // server, not a PID recycled by the OS.
  struct stat exe_stat_ = {};

  ~ForkServerProps() {
    for (int i = 0; i < 2; ++i) {
      if (pipe_[i] >= 0 && close(pipe_[i]) != 0) {
        LOG(ERROR) << "Failed to close fork server pipe for " << fifo_path_[i];
      }
      std::error_code ec;
      if (!fifo_path_[i].empty() &&
          !std::filesystem::remove(fifo_path_[i], ec)) {
        LOG(ERROR) << "Failed to remove fork server pipe file " << fifo_path_[i]
                   << ": " << ec;
      }
    }
  }
};

// NOTE: Because std::unique_ptr<T> requires T to be a complete type wherever
// the deleter is instantiated, the special member functions must be defined
// out-of-line here, now that ForkServerProps is complete (that's by-the-book
// PIMPL).
Command::Command(Command &&other) noexcept = default;
Command::~Command() = default;

Command::Command(std::string_view path, std::vector<std::string> args,
                 std::vector<std::string> env, std::string_view out,
                 std::string_view err, absl::Duration timeout,
                 std::string_view temp_file_path)
    : path_(path),
      args_(std::move(args)),
      env_(std::move(env)),
      out_(out),
      err_(err),
      timeout_(timeout),
      temp_file_path_(temp_file_path) {}

std::string Command::ToString() const {
  std::vector<std::string> ss;
  // env.
  ss.reserve(env_.size());
  for (const auto &env : env_) {
    ss.emplace_back(env);
  }
  // path.
  std::string path = path_;
  // Strip the % prefixes, if any.
  if (absl::StartsWith(path, kNoForkServerRequestPrefix)) {
    path = path.substr(kNoForkServerRequestPrefix.size());
  }
  // Replace @@ with temp_file_path_.
  constexpr std::string_view kTempFileWildCard = "@@";
  if (absl::StrContains(path, kTempFileWildCard)) {
    CHECK(!temp_file_path_.empty());
    path = absl::StrReplaceAll(path, {{kTempFileWildCard, temp_file_path_}});
  }
  ss.emplace_back(path);
  // args.
  for (const auto &arg : args_) {
    ss.emplace_back(arg);
  }
  // out/err.
  if (!out_.empty()) {
    ss.emplace_back(absl::StrCat("> ", out_));
  }
  if (!err_.empty()) {
    if (out_ != err_) {
      ss.emplace_back(absl::StrCat("2> ", err_));
    } else {
      ss.emplace_back("2>&1");
    }
  }
  // Trim trailing space and return.
  return absl::StrJoin(ss, kCommandLineSeparator);
}

bool Command::StartForkServer(std::string_view temp_dir_path,
                              std::string_view prefix) {
  if (absl::StartsWith(path_, kNoForkServerRequestPrefix)) {
    VLOG(2) << "Fork server disabled for " << path();
    return false;
  }
  VLOG(2) << "Starting fork server for " << path();

  fork_server_.reset(new ForkServerProps);
  fork_server_->fifo_path_[0] = std::filesystem::path(temp_dir_path)
                                    .append(absl::StrCat(prefix, "_FIFO0"));
  fork_server_->fifo_path_[1] = std::filesystem::path(temp_dir_path)
                                    .append(absl::StrCat(prefix, "_FIFO1"));
  const std::string pid_file_path =
      std::filesystem::path(temp_dir_path).append("pid");
  (void)std::filesystem::create_directory(temp_dir_path);  // it may not exist.
  for (int i = 0; i < 2; ++i) {
    PCHECK(mkfifo(fork_server_->fifo_path_[i].c_str(), 0600) == 0)
        << VV(i) << VV(fork_server_->fifo_path_[i]);
  }

  // NOTE: A background process does not return its exit status to the subshell,
  // so failures will never propagate to the caller of `system()`. Instead, we
  // save out the background process's PID to a file and use it later to assert
  // that the process has started and is still running.
  static constexpr std::string_view kForkServerCommandStub = R"sh(
  {
    CENTIPEDE_FORK_SERVER_FIFO0="%s" \
    CENTIPEDE_FORK_SERVER_FIFO1="%s" \
    %s
  } &
  printf "%%s" $! > "%s"
)sh";
  const std::string fork_server_command = absl::StrFormat(
      kForkServerCommandStub, fork_server_->fifo_path_[0],
      fork_server_->fifo_path_[1], command_line_, pid_file_path);
  VLOG(2) << "Fork server command:" << fork_server_command;

  const int exit_code = system(fork_server_command.c_str());

  // Check if `system()` was able to parse and run the command at all.
  if (exit_code != EXIT_SUCCESS) {
    LogProblemInfo(
        "Failed to parse or run command to launch fork server; will proceed "
        "without it");
    return false;
  }

  // The fork server is probably running now. However, one failure scenario is
  // that it starts and exits early. Try opening the read/write comms pipes with
  // it: if that fails, something is wrong.
  // We use non-blocking I/O to open the pipes. That is good and safe, because:
  // 1) This prevents the `open()` calls from hanging when the fork server fails
  // to open the pipes on its side (note the use of O_RDWR, not O_WRONLY, to
  // avoid ENXIO).
  // 2) In `Command::Execute`, we wait for the return channel pipe with a
  // `poll()`, so it should always have data when we attempt to `read()` from
  // it.
  // See more at
  // https://www.gnu.org/software/libc/manual/html_node/Operating-Modes.html.
  if ((fork_server_->pipe_[0] = open(fork_server_->fifo_path_[0].c_str(),
                                     O_RDWR | O_NONBLOCK)) < 0 ||
      (fork_server_->pipe_[1] = open(fork_server_->fifo_path_[1].c_str(),
                                     O_RDONLY | O_NONBLOCK)) < 0) {
    LogProblemInfo(
        "Failed to establish communication with fork server; will proceed "
        "without it");
    return false;
  }

  std::string pid_str;
  ReadFromLocalFile(pid_file_path, pid_str);
  CHECK(absl::SimpleAtoi(pid_str, &fork_server_->pid_)) << VV(pid_str);

  // TODO(b/281882892): Disable for now. Find a proper solution later.
  if constexpr (false) {
    // The fork server has started and the comms pipes got opened successfully.
    // Read the fork server's PID and the initial /proc/<PID>/exe symlink
    // pointing at the fork server's binary, written to the provided files by
    // `command`. `Execute()` uses these to monitor the fork server health.
    std::string proc_exe = absl::StrFormat("/proc/%d/exe", fork_server_->pid_);
    if (stat(proc_exe.c_str(), &fork_server_->exe_stat_) != EXIT_SUCCESS) {
      LogProblemInfo(absl::StrCat(
          "Fork server appears not running; will proceed without it "
          "(failed to stat ",
          proc_exe, ")"));
      return false;
    }
  }

  return true;
}

absl::Status Command::VerifyForkServerIsHealthy() {
  // Preconditions: the callers (`Execute()`) should call us only when the fork
  // server is presumed to be running (`fork_server_pid_` >= 0). If it is, the
  // comms pipes are guaranteed to be opened by `StartForkServer()`.
  CHECK(fork_server_ != nullptr) << "Fork server wasn't started";
  CHECK(fork_server_->pid_ >= 0) << "Fork server process failed to start";
  CHECK(fork_server_->pipe_[0] >= 0 && fork_server_->pipe_[1] >= 0)
      << "Failed to connect to fork server";

  // A process with the fork server PID exists (_some_ process, possibly with a
  // recycled PID)...
  if (kill(fork_server_->pid_, 0) != EXIT_SUCCESS) {
    return absl::UnknownError(absl::StrCat(
        "Can't communicate with fork server, PID=", fork_server_->pid_));
  }
  // TODO(b/281882892): Disable for now. Find a proper solution later.
  if constexpr (false) {
    // ...and it is a process with our expected binary, so it's practically
    // guaranteed to be our original fork server process.
    const std::string proc_exe =
        absl::StrFormat("/proc/%d/exe", fork_server_->pid_);
    struct stat proc_exe_stat = {};
    if (stat(proc_exe.c_str(), &proc_exe_stat) != EXIT_SUCCESS) {
      return absl::UnknownError(absl::StrCat(
          "Failed to stat fork server's /proc/<PID>/exe symlink, PID=",
          fork_server_->pid_));
    }
    if (proc_exe_stat.st_dev != fork_server_->exe_stat_.st_dev ||
        proc_exe_stat.st_ino != fork_server_->exe_stat_.st_ino) {
      return absl::UnknownError(absl::StrCat(
          "Fork server's /proc/<PID>/exe symlink changed (new process?), PID=",
          fork_server_->pid_));
    }
  }
  return absl::OkStatus();
}

int Command::Execute() {
  VLOG(1) << "Executing command '" << command_line_ << "'...";

  int exit_code = EXIT_SUCCESS;

  if (fork_server_ != nullptr) {
    VLOG(1) << "Sending execution request to fork server: " << VV(timeout_);

    if (const auto status = VerifyForkServerIsHealthy(); !status.ok()) {
      LogProblemInfo(absl::StrCat("Fork server should be running, but isn't: ",
                                  status.message()));
      return EXIT_FAILURE;
    }

    // Wake up the fork server.
    char x = ' ';
    CHECK_EQ(1, write(fork_server_->pipe_[0], &x, 1));

    // The fork server forks, the child is running. Block until some readable
    // data appears in the pipe (that is, after the fork server writes the
    // execution result to it).
    struct pollfd poll_fd = {};
    int poll_ret = -1;
    auto poll_deadline = absl::Now() + timeout_;
    // The `poll()` syscall can get interrupted: it sets errno==EINTR in that
    // case. We should tolerate that.
    do {
      // NOTE: `poll_fd` has to be reset every time.
      poll_fd = {
          .fd = fork_server_->pipe_[1],  // The file descriptor to wait for.
          .events = POLLIN,              // Wait until `fd` gets readable data.
      };
      const int poll_timeout_ms = static_cast<int>(absl::ToInt64Milliseconds(
          std::max(poll_deadline - absl::Now(), absl::Milliseconds(1))));
      poll_ret = poll(&poll_fd, 1, poll_timeout_ms);
    } while (poll_ret < 0 && errno == EINTR);

    if (poll_ret != 1 || (poll_fd.revents & POLLIN) == 0) {
      // The fork server errored out or timed out, or some other error occurred,
      // e.g. the syscall was interrupted.
      if (poll_ret == 0) {
        LogProblemInfo(
            absl::StrCat("Timeout while waiting for fork server: timeout is ",
                         absl::FormatDuration(timeout_)));
      } else {
        LogProblemInfo(absl::StrCat(
            "Error while waiting for fork server: poll() returned ", poll_ret));
      }
      return EXIT_FAILURE;
    }

    // The fork server wrote the execution result to the pipe: read it.
    CHECK_EQ(sizeof(exit_code),
             read(fork_server_->pipe_[1], &exit_code, sizeof(exit_code)));
  } else {
    VLOG(1) << "Fork server disabled - executing command directly";
    // No fork server, use system().
    exit_code = system(command_line_.c_str());
  }

  // When the command is actually a wrapper shell launching the binary(-es)
  // (e.g. a Docker container), the shell will preserve a normal exit code
  // returned by the binary (the legal range for such codes that can be
  // passed to `exit()` is [0..125]); but the shell will specially encode
  // the exit code returned by the binary when the binary is killed by a
  // signal by adding 128 to the signal number and returning the result as
  // a normal exit code. This encoding is used in `bash` and `dash` but may be
  // different in other shells, e.g., `ksh`.
  //
  // For more details, see https://tldp.org/LDP/abs/html/exitcodes.html.
  //
  // Therefore, to handle this case, we need to first unpack these special
  // pseudo-normal exit codes before analyzing them further. After
  // reassigning `WEXITSTATUS()` to exit_code, the if-else below will take
  // the else-branch and unpack the signal number from the updated value. This
  // has experimentally been observed to work with existing implementations of
  // the `wait` macros but there is no definitive documentation for it.
  if (WIFEXITED(exit_code) && WEXITSTATUS(exit_code) > 128 &&
      WEXITSTATUS(exit_code) < 255) {
    exit_code = WEXITSTATUS(exit_code);
  }

  if (WIFEXITED(exit_code) && WEXITSTATUS(exit_code) != EXIT_SUCCESS) {
    const auto exit_status = WEXITSTATUS(exit_code);
    VlogProblemInfo(
        absl::StrCat("Command errored out: exit status=", exit_status),
        /*vlog_level=*/1);
    exit_code = exit_status;
  } else if (WIFSIGNALED(exit_code)) {
    const auto signal = WTERMSIG(exit_code);
    if (signal == SIGINT) {
      RequestEarlyExit(EXIT_FAILURE);
      // When the user kills Centipede via ^C, they are unlikely to be
      // interested in any of the subprocesses' outputs. Also, ^C terminates all
      // the subprocesses, including all the runners, so all their outputs would
      // get printed simultaneously, flooding the log. Hence log at a high
      // `vlog_level`.
      VlogProblemInfo("Command killed: signal=SIGINT (likely Ctrl-C)",
                      /*vlog_level=*/10);
    } else {
      // The fork server subprocess was killed by something other than ^C: log
      // at a lower `vlog_level` to help diagnose problems.
      VlogProblemInfo(absl::StrCat("Command killed: signal=", signal),
                      /*vlog_level=*/1);
    }

    // TODO(ussuri): Consider changing this to exit_code = EXIT_FAILURE.
    exit_code = signal;
  }

  return exit_code;
}

std::string Command::ReadRedirectedStdout() const {
  std::string ret;
  if (!out_.empty()) {
    ReadFromLocalFile(out_, ret);
    if (ret.empty()) ret = "<EMPTY>";
  }
  return ret;
}

std::string Command::ReadRedirectedStderr() const {
  std::string ret;
  if (!err_.empty()) {
    if (err_ == "2>&1" || err_ == out_) {
      ret = "<DUPED TO STDOUT>";
    } else {
      ReadFromLocalFile(err_, ret);
      if (ret.empty()) ret = "<EMPTY>";
    }
  }
  return ret;
}

void Command::LogProblemInfo(std::string_view message) const {
  // Prevent confusing interlaced logs when multiple threads experience failures
  // at the same time.
  // TODO(ussuri): Non-failure related logs from other threads may still
  //  interlace with these. Improve further, if possible. Note the printiing
  //  line-by-line is unavoidable to overcome the single log line length limit.
  static absl::Mutex mu{absl::kConstInit};
  absl::MutexLock lock(&mu);

  LOG(ERROR) << message;
  LOG(ERROR).NoPrefix() << "=== COMMAND ===";
  LOG(ERROR).NoPrefix() << command_line_;
  LOG(ERROR).NoPrefix() << "=== STDOUT ===";
  for (const auto &line : absl::StrSplit(ReadRedirectedStdout(), '\n')) {
    LOG(ERROR).NoPrefix() << line;
  }
  LOG(ERROR).NoPrefix() << "=== STDERR ===";
  for (const auto &line : absl::StrSplit(ReadRedirectedStderr(), '\n')) {
    LOG(ERROR).NoPrefix() << line;
  }
}

void Command::VlogProblemInfo(std::string_view message, int vlog_level) const {
  if (ABSL_VLOG_IS_ON(vlog_level)) LogProblemInfo(message);
}

}  // namespace centipede
