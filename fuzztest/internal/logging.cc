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

#include "./fuzztest/internal/logging.h"

#include <errno.h>
#include <string.h>

#include "absl/base/attributes.h"
#include "absl/base/const_init.h"
#include "absl/base/thread_annotations.h"
#include "absl/synchronization/mutex.h"
#include "./common/logging.h"

#if defined(__linux__) || defined(__APPLE__)
#include <fcntl.h>
#include <unistd.h>
#endif

#include <cstdio>
#include <cstdlib>
#include <string>

namespace fuzztest::internal {

#if defined(__linux__) || defined(__APPLE__)

namespace {

// Returns a duplicate of `fd` with the close-on-exec flag set, or returns -1
// if duplication fails.
//
// This function is signal-safe.
int DupLocally(int fd) {
  int dup_fd = dup(fd);
  // Error conditions below are extremely unlikely, so we don't spend too much
  // effort in handling/logging them.
  if (dup_fd == -1) {
    constexpr char msg[] = "[!] dup() failed in DupLocally(), returning -1\n";
    (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
    return -1;
  }
  int flags = fcntl(dup_fd, F_GETFD);
  if (flags == -1) {
    constexpr char msg[] =
        "[!] fcntl(F_GETFD) failed in DupLocally(), ignoring the "
        "error..\n";
    (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
    return dup_fd;
  }
  flags |= FD_CLOEXEC;
  if (fcntl(dup_fd, F_SETFD, flags) == -1) {
    constexpr char msg[] =
        "[!] fcntl(F_SETFD) failed in DupLocally(), ignoring the "
        "error..\n";
    (void)write(STDERR_FILENO, msg, sizeof(msg) - 1);
  }
  return dup_fd;
}

ABSL_CONST_INIT absl::Mutex stderr_file_guard_(absl::kConstInit);
FILE* stderr_file_ ABSL_GUARDED_BY(stderr_file_guard_);  // Zero-initialized.

FILE* stdout_file_ = stdout;  // Never accessed concurrently.

}  // namespace

int GetStderrFdDup() {
  static int fd = DupLocally(STDERR_FILENO);
  return fd;
}

FILE* GetStderr() {
  absl::MutexLock lock(stderr_file_guard_);
  if (!stderr_file_) {
    stderr_file_ = stderr;
  }
  return stderr_file_;
}

namespace {

int GetStdoutFdDup() {
  static int fd = DupLocally(STDOUT_FILENO);
  return fd;
}

[[maybe_unused]] const auto force_get_stderr_fd_dup_early = GetStderrFdDup();
[[maybe_unused]] const auto force_get_stdout_fd_dup_early = GetStdoutFdDup();

void Silence(int fd) {
  FILE* tmp = fopen("/dev/null", "w");
  FUZZTEST_PCHECK(tmp) << "fopen() error";
  FUZZTEST_PCHECK(dup2(fileno(tmp), fd) != -1) << "dup2() error";
  FUZZTEST_PCHECK(fclose(tmp) == 0) << "fclose() error";
}

// Only accepts 1 or 2 (stdout or stderr).
// If it's stdout, silence it after duping it as a global temporary, which
// will be used when restoring the stdout.
// If it's a stderr, silence it after duping it as the global stderr, which
// will be used internally to log and be used when restoring the stderr.
void DupAndSilence(int fd) {
  FUZZTEST_CHECK(fd == STDOUT_FILENO || fd == STDERR_FILENO)
      << "DupAndSilence only accepts stderr or stdout.";
  if (fd == STDOUT_FILENO) {
    FUZZTEST_CHECK(GetStdoutFdDup() != -1) << "GetStdoutFdDup() fails.";
    stdout_file_ = fdopen(GetStdoutFdDup(), "w");
    FUZZTEST_PCHECK(stdout_file_) << "fdopen(GetStdoutFdDup()) error";
  } else {
    FUZZTEST_CHECK(GetStderrFdDup() != -1) << "GetStderrFdDup() fails.";
    auto file = fdopen(GetStderrFdDup(), "w");
    FUZZTEST_PCHECK(file) << "fdopen(GetStderrFdDup()) error";
    absl::MutexLock lock(stderr_file_guard_);
    stderr_file_ = file;
  }
  Silence(fd);
}

}  // namespace

void SilenceTargetStdoutAndStderr() {
  DupAndSilence(STDOUT_FILENO);
  DupAndSilence(STDERR_FILENO);
}

void RestoreTargetStdoutAndStderr() {
  // The CHECK-s below call GetStderr(), which accesses stderr_file_, which
  // would lead to a deadlock if we kept the guard locked and the CHECK-s
  // failed. To avoid this, we use a local variable.
  stderr_file_guard_.lock();
  FILE* silenced_stderr = stderr_file_;
  stderr_file_ = stderr;
  stderr_file_guard_.unlock();
  FUZZTEST_CHECK(silenced_stderr != stderr)
      << "RestoreStderr was called without calling DupandSilenceStderr first.";
  FUZZTEST_PCHECK(dup2(fileno(silenced_stderr), STDERR_FILENO) != -1);
  FUZZTEST_PCHECK(fclose(silenced_stderr) == 0);
  FUZZTEST_CHECK(stdout_file_ != stdout)
      << "RestoreStdout was called without calling DupandSilenceStdout first.";
  FUZZTEST_PCHECK(dup2(fileno(stdout_file_), STDOUT_FILENO) != -1);
  FUZZTEST_PCHECK(fclose(stdout_file_) == 0);
  stdout_file_ = stdout;
}

bool IsSilenceTargetEnabled() {
  return absl::NullSafeStringView(getenv("FUZZTEST_SILENCE_TARGET")) == "1";
}

#else  // defined(__linux) || defined(__APPLE__)

int GetStderrFdDup() { return -1; }

FILE* GetStderr() { return stderr; }

void SilenceTargetStdoutAndStderr() { return; }

void RestoreTargetStdoutAndStderr() { return; }

bool IsSilenceTargetEnabled() { return false; }

#endif  // defined(__linux) || defined(__APPLE__)

void Abort(const char* file, int line, const std::string& message) {
  fprintf(GetStderr(), "%s:%d: %s\n", file, line, message.c_str());
  std::abort();
}

const std::string* volatile test_abort_message = nullptr;
void AbortInTest(const std::string& message) {
  // When we are within a test, we set the message here and call abort().
  // The signal handler will pickup the message and print it at the right time.
  test_abort_message = &message;
  std::abort();
}

}  // namespace fuzztest::internal
