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
#include <spawn.h>
#include <sys/poll.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
#include <inttypes.h>
#include <libproc.h>
#endif  // __APPLE__

#include <algorithm>
#include <csignal>
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>  // NOLINT
#include <utility>
#include <vector>

#include "absl/base/const_init.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
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
#include "./centipede/stop.h"
#include "./centipede/util.h"
#include "./common/logging.h"

#if !defined(_MSC_VER)
// Needed to pass the current environment to posix_spawn, which needs an
// explicit envp without an option to inherit implicitly.
extern char** environ;
#endif

namespace fuzztest::internal {
namespace {

// See the definition of --fork_server flag.
constexpr std::string_view kCommandLineSeparator(" \\\n");
constexpr std::string_view kNoForkServerRequestPrefix("%f");

absl::StatusOr<std::string> GetProcessCreationStamp(pid_t pid) {
#ifdef __APPLE__
  struct proc_bsdinfo info = {};
  if (proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, PROC_PIDTBSDINFO_SIZE) !=
      PROC_PIDTBSDINFO_SIZE) {
    return absl::InternalError(
        absl::StrCat("failed to get proc bsdinfo for ", pid));
  }
  return absl::StrFormat("%" PRIu64 ".%06" PRIu64, info.pbi_start_tvsec,
                         info.pbi_start_tvusec);
#else
  constexpr int kFieldIndexOfStartTimeAfterComm = 19;  // From `man procfs`
  const std::string proc_stat_path = absl::StrFormat("/proc/%d/stat", pid);
  std::string proc_stat_line;
  // Cannot use `ReadFromLocalFile` on procfs since seek does not work.
  // This seems to work assuming the filename of the command does not contain
  // newline, which should be in our control when the process is ours.
  if (std::getline(std::ifstream(proc_stat_path), proc_stat_line).bad()) {
    return absl::InternalError(absl::StrCat("failed to read ", proc_stat_path));
  }
  // According to the current format of `/proc/[pid]/stat`, only the comm field
  // can contain ')'.
  const size_t comm_end_pos = proc_stat_line.find_last_of(')');
  if (comm_end_pos == proc_stat_line.npos) {
    return absl::NotFoundError(
        absl::StrCat("cannot find the end of command in the first line of ",
                     proc_stat_path, ": ", proc_stat_line));
  }
  std::string_view proc_stat_after_comm =
      std::string_view(proc_stat_line).substr(comm_end_pos + 1);
  const std::vector<std::string_view> fields =
      absl::StrSplit(proc_stat_after_comm, ' ', absl::SkipEmpty());
  if (fields.size() <= kFieldIndexOfStartTimeAfterComm) {
    return absl::NotFoundError(
        absl::StrCat("not enough fields in the first line of ", proc_stat_path,
                     ": ", proc_stat_line));
  }
  return std::string(fields[kFieldIndexOfStartTimeAfterComm]);
#endif
}

}  // namespace

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
  // The creation stamp of the fork server process. Used to detect that the
  // running process with `pid_` is still the original fork server, not a PID
  // recycled by the OS.
  std::string creation_stamp;

  template <typename T>
  bool ReadPipe(absl::Time deadline, T& out) {
    struct pollfd poll_fd = {};
    int poll_ret = -1;
    do {
      poll_fd = {
          /*fd=*/pipe_[1],
          /*events=*/POLLIN,
      };
      const int poll_timeout_ms = static_cast<int>(absl::ToInt64Milliseconds(
          std::max(deadline - absl::Now(), absl::Milliseconds(1))));
      poll_ret = poll(&poll_fd, 1, poll_timeout_ms);
      // The `poll()` syscall can get interrupted: it sets errno==EINTR in that
      // case. We should tolerate that.
    } while (poll_ret < 0 && errno == EINTR);
    if (poll_ret == 1 && (poll_fd.revents & POLLIN)) {
      FUZZTEST_CHECK_EQ(sizeof(T), read(pipe_[1], &out, sizeof(T)));
      return true;
    } else if (poll_ret == 0) {
      FUZZTEST_LOG(ERROR) << "poll timed out on fork server pipe";
    } else {
      FUZZTEST_PLOG(ERROR) << "poll on fork server pipe returned " << poll_ret;
    }
    return false;
  }

  ~ForkServerProps() {
    for (int i = 0; i < 2; ++i) {
      if (pipe_[i] >= 0 && close(pipe_[i]) != 0) {
        FUZZTEST_LOG(ERROR)
            << "Failed to close fork server pipe for " << fifo_path_[i];
      }
      std::error_code ec;
      if (!fifo_path_[i].empty() &&
          !std::filesystem::remove(fifo_path_[i], ec)) {
        FUZZTEST_LOG(ERROR) << "Failed to remove fork server pipe file "
                            << fifo_path_[i] << ": " << ec;
      }
    }
  }
};

// NOTE: Because std::unique_ptr<T> requires T to be a complete type wherever
// the deleter is instantiated, the special member functions must be defined
// out-of-line here, now that ForkServerProps is complete (that's by-the-book
// PIMPL).
Command::~Command() {
  if (is_executing()) {
    FUZZTEST_LOG(WARNING)
        << "Destructing Command object for " << path() << " with "
        << (fork_server_ ? absl::StrCat("fork server PID ", fork_server_->pid_)
                         : absl::StrCat("PID ", pid_))
        << " still running. Requesting it to stop without waiting for it...";
    RequestStop();
  }
}

Command::Command(std::string_view path, Options options)
    : path_(path), options_(std::move(options)) {}

Command::Command(std::string_view path) : Command{path, {}} {}

std::string Command::ToString() const {
  std::vector<std::string> ss;
  ss.reserve(/*env*/ 1 + options_.env_add.size() + options_.env_remove.size() +
             /*path*/ 1 + /*args*/ options_.args.size() + /*out/err*/ 2);
  // env.
  ss.push_back("env");
  // Arguments that unset environment variables must appear first.
  for (const auto& var : options_.env_remove) {
    ss.push_back(absl::StrCat("-u ", var));
  }
  for (const auto& var : options_.env_add) {
    ss.push_back(var);
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
    FUZZTEST_CHECK(!options_.temp_file_path.empty());
    path = absl::StrReplaceAll(path,
                               {{kTempFileWildCard, options_.temp_file_path}});
  }
  ss.push_back(std::move(path));
  // args.
  for (const auto& arg : options_.args) {
    ss.push_back(arg);
  }
  // out/err.
  if (!options_.stdout_file.empty()) {
    ss.push_back(absl::StrCat("> ", options_.stdout_file));
  }
  if (!options_.stderr_file.empty()) {
    if (options_.stdout_file != options_.stderr_file) {
      ss.push_back(absl::StrCat("2> ", options_.stderr_file));
    } else {
      ss.push_back("2>&1");
    }
  }
  // Trim trailing space and return.
  return absl::StrJoin(ss, kCommandLineSeparator);
}

bool Command::StartForkServer(std::string_view temp_dir_path,
                              std::string_view prefix) {
  if (absl::StartsWith(path_, kNoForkServerRequestPrefix)) {
    FUZZTEST_VLOG(2) << "Fork server disabled for " << path();
    return false;
  }
  FUZZTEST_VLOG(2) << "Starting fork server for " << path();

  fork_server_.reset(new ForkServerProps);
  fork_server_->fifo_path_[0] = std::filesystem::path(temp_dir_path)
                                    .append(absl::StrCat(prefix, "_FIFO0"));
  fork_server_->fifo_path_[1] = std::filesystem::path(temp_dir_path)
                                    .append(absl::StrCat(prefix, "_FIFO1"));
  const std::string pid_file_path =
      std::filesystem::path(temp_dir_path).append("pid");
  (void)std::filesystem::create_directory(temp_dir_path);  // it may not exist.
  for (int i = 0; i < 2; ++i) {
    FUZZTEST_PCHECK(mkfifo(fork_server_->fifo_path_[i].c_str(), 0600) == 0)
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
    exec %s
  } &
  printf "%%s" $! > "%s"
)sh";
  const std::string fork_server_command = absl::StrFormat(
      kForkServerCommandStub, fork_server_->fifo_path_[0],
      fork_server_->fifo_path_[1], command_line_, pid_file_path);
  FUZZTEST_VLOG(2) << "Fork server command:" << fork_server_command;

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
  FUZZTEST_CHECK(absl::SimpleAtoi(pid_str, &fork_server_->pid_)) << VV(pid_str);
  auto creation_stamp = GetProcessCreationStamp(fork_server_->pid_);
  if (!creation_stamp.ok()) {
    LogProblemInfo(
        absl::StrCat("Failed to get the fork server's creation stamp; will "
                     "proceed without it "
                     "(failure status: ",
                     creation_stamp.status(), ")"));
    return false;
  }
  fork_server_->creation_stamp = *std::move(creation_stamp);
  return true;
}

absl::Status Command::VerifyForkServerIsHealthy() {
  // Preconditions: the callers (`Execute()`) should call us only when the fork
  // server is presumed to be running (`fork_server_pid_` >= 0). If it is, the
  // comms pipes are guaranteed to be opened by `StartForkServer()`.
  FUZZTEST_CHECK(fork_server_ != nullptr) << "Fork server wasn't started";
  FUZZTEST_CHECK(fork_server_->pid_ >= 0)
      << "Fork server process failed to start";
  FUZZTEST_CHECK(fork_server_->pipe_[0] >= 0 && fork_server_->pipe_[1] >= 0)
      << "Failed to connect to fork server";

  // A process with the fork server PID exists (_some_ process, possibly with a
  // recycled PID)...
  if (kill(fork_server_->pid_, 0) != EXIT_SUCCESS) {
    return absl::UnknownError(absl::StrCat(
        "Can't communicate with fork server, PID=", fork_server_->pid_));
  }
  // ...and it is a process has the same creation stamp, so it's practically
  // guaranteed to be our original fork server process.
  const auto creation_stamp = GetProcessCreationStamp(fork_server_->pid_);
  if (!creation_stamp.ok()) return creation_stamp.status();
  if (*creation_stamp != fork_server_->creation_stamp) {
    return absl::UnknownError(absl::StrCat(
        "Fork server's creation stamp changed (new process?) - expected ",
        fork_server_->creation_stamp, ", but got ", *creation_stamp));
  }
  return absl::OkStatus();
}

bool Command::ExecuteAsync() {
  FUZZTEST_CHECK(!is_executing());
  FUZZTEST_VLOG(1) << "Executing command '" << command_line_ << "'...";

  if (fork_server_ != nullptr) {
    FUZZTEST_VLOG(1) << "Sending execution request to fork server";

    if (const auto status = VerifyForkServerIsHealthy(); !status.ok()) {
      LogProblemInfo(absl::StrCat("Fork server should be running, but isn't: ",
                                  status.message()));
      return false;
    }

    // Wake up the fork server.
    char x = ' ';
    FUZZTEST_CHECK_EQ(1, write(fork_server_->pipe_[0], &x, 1));
    // Read the one-byte ack.
    // Use 60s as an arbitrary duration to wait for the process to load and
    // enter the fork server.
    FUZZTEST_CHECK(fork_server_->ReadPipe(absl::Now() + absl::Seconds(60), x));
  } else {
    FUZZTEST_CHECK_EQ(pid_, -1);
    std::vector<std::string> argv_strs = {"/bin/sh", "-c", command_line_};
    std::vector<char*> argv;
    argv.reserve(argv_strs.size() + 1);
    for (auto& argv_str : argv_strs) {
      argv.push_back(argv_str.data());
    }
    argv.push_back(nullptr);
    FUZZTEST_PCHECK(posix_spawn(&pid_, argv[0], /*file_actions=*/nullptr,
                                /*attrp=*/nullptr, argv.data(), environ) == 0);
  }

  is_executing_ = true;
  return true;
}

std::optional<int> Command::Wait(absl::Time deadline) {
  FUZZTEST_CHECK(is_executing());
  int exit_code = EXIT_SUCCESS;

  if (fork_server_ != nullptr) {
    // The fork server forks, the child is running. Block until some readable
    // data appears in the pipe (that is, after the fork server writes the
    // execution result to it).
    if (!fork_server_->ReadPipe(deadline, exit_code)) {
      VlogProblemInfo(
          absl::StrCat("Waiting for fork server failed, deadline is ",
                       deadline),
          /*vlog_level=*/1);
      return std::nullopt;
    }
  } else {
    FUZZTEST_CHECK_NE(pid_, -1);
    while (true) {
      const pid_t r = waitpid(pid_, &exit_code, WNOHANG);
      FUZZTEST_CHECK_NE(r, -1);
      if (r == pid_ && (WIFEXITED(exit_code) || WIFSIGNALED(exit_code))) break;
      FUZZTEST_CHECK_EQ(r, 0);
      const auto timeout = deadline - absl::Now();
      if (timeout > absl::ZeroDuration()) {
        const auto duration = std::clamp<useconds_t>(
            absl::ToInt64Microseconds(timeout), 0, 100000);
        usleep(duration);  // NOLINT: early return on SIGCHLD is desired.
        continue;
      } else {
        VlogProblemInfo(
            absl::StrCat(
                "Timeout while waiting for the command process: deadline is ",
                deadline),
            /*vlog_level=*/1);
        return std::nullopt;
      }
    }
    pid_ = -1;
  }
  is_executing_ = false;

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
      RequestEarlyStop(EXIT_FAILURE);
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

void Command::RequestStop() {
  FUZZTEST_CHECK(is_executing());
  if (fork_server_) {
    FUZZTEST_CHECK_NE(fork_server_->pid_, -1);
    kill(fork_server_->pid_, SIGTERM);
    return;
  }
  FUZZTEST_CHECK_NE(pid_, -1);
  kill(pid_, SIGTERM);
}

std::string Command::ReadRedirectedStdout() const {
  std::string ret;
  if (!options_.stdout_file.empty()) {
    ReadFromLocalFile(options_.stdout_file, ret);
    if (ret.empty()) ret = "<EMPTY>";
  }
  return ret;
}

std::string Command::ReadRedirectedStderr() const {
  std::string ret;
  if (!options_.stderr_file.empty()) {
    if (options_.stderr_file == "2>&1" ||
        options_.stderr_file == options_.stdout_file) {
      ret = "<DUPED TO STDOUT>";
    } else {
      ReadFromLocalFile(options_.stderr_file, ret);
      if (ret.empty()) ret = "<EMPTY>";
    }
  }
  return ret;
}

void Command::LogProblemInfo(std::string_view message) const {
  absl::MutexLock lock(&GetExecutionLoggingMutex());

  FUZZTEST_LOG(ERROR) << message;
  FUZZTEST_LOG(ERROR).NoPrefix() << "=== COMMAND ===";
  FUZZTEST_LOG(ERROR).NoPrefix() << command_line_;
  FUZZTEST_LOG(ERROR).NoPrefix() << "=== STDOUT ===";
  for (const auto& line : absl::StrSplit(ReadRedirectedStdout(), '\n')) {
    FUZZTEST_LOG(ERROR).NoPrefix() << line;
  }
  FUZZTEST_LOG(ERROR).NoPrefix() << "=== STDERR ===";
  for (const auto& line : absl::StrSplit(ReadRedirectedStderr(), '\n')) {
    FUZZTEST_LOG(ERROR).NoPrefix() << line;
  }
}

void Command::VlogProblemInfo(std::string_view message, int vlog_level) const {
  if (FUZZTEST_VLOG_IS_ON(vlog_level)) LogProblemInfo(message);
}

absl::Mutex& GetExecutionLoggingMutex() {
  static absl::Mutex mu{absl::kConstInit};
  return mu;
}

}  // namespace fuzztest::internal
