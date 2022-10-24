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

#include "./fuzztest/internal/runtime.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iterator>
#include <string>

#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "./fuzztest/internal/io.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/type_support.h"

#ifdef ADDRESS_SANITIZER
#include <sanitizer/asan_interface.h>
#endif

namespace fuzztest::internal {

RunMode run_mode = RunMode::kUnitTest;
ABSL_CONST_INIT absl::Duration fuzz_time_limit = absl::InfiniteDuration();
std::atomic<bool> external_failure_was_detected;
std::atomic<bool> termination_requested;
OnFailure on_failure;
void (*crash_handler_hook)();

void OnFailure::DumpReproducer(std::string_view outdir) const {
  const std::string filename =
      WriteDataToDir(current_args_.Visit(ArgumentSerializeVisitor{}), outdir);
  if (filename.empty()) {
    absl::FPrintF(GetStderr(), "[!] Failed to write reproducer file.\n");
  } else {
    absl::FPrintF(GetStderr(), "[*] Reproducer file written to: %s\n",
                  filename);
  }
}

void OnFailure::PrintFinalStats(absl::FormatRawSink out) const {
  const std::string separator = '\n' + std::string(65, '=') + '\n';
  absl::Format(out, "%s=== Fuzzing stats\n\n", separator);

  const absl::Duration fuzzing_time = clock_fn_() - stats_->start_time;
  absl::Format(out, "Elapsed seconds (ns): %d\n",
               absl::ToInt64Nanoseconds(fuzzing_time));
  absl::Format(out, "Total runs: %d\n", stats_->runs);
  absl::Format(out, "Edges covered: %d\n", stats_->edges_covered);
  absl::Format(out, "Total edges: %d\n", stats_->total_edges);
  absl::Format(out, "Corpus size: %d\n", stats_->useful_inputs);
}

void OnFailure::PrintReport(absl::FormatRawSink out) const {
  // We don't want to try and print a fuzz report when we are not running a fuzz
  // test, even if we got a crash.
  if (!enabled_) return;

  if (crash_handler_hook) crash_handler_hook();

  // First, lets try to dump the reproducer if requested.
  if (current_args_.has_value()) {
    const char* outdir = getenv("FUZZTEST_REPRODUCERS_OUT_DIR");
    if (outdir != nullptr && outdir[0]) {
      DumpReproducer(outdir);
    }
  }

  if (run_mode != RunMode::kUnitTest) {
    PrintFinalStats(out);
  }

  const std::string separator = '\n' + std::string(65, '=') + '\n';

  if (current_args_.has_value()) {
    absl::Format(out, "%s=== BUG FOUND!\n\n", separator);
    absl::Format(out, "%s:%d: Counterexample found for %s.%s.\n", test_->file(),
                 test_->line(), test_->suite_name(), test_->test_name());
    absl::Format(out, "The test fails with input:\n");
    for (size_t i = 0; i < num_args_; ++i) {
      absl::Format(out, "argument %d: ", i);
      current_args_.Visit(ArgumentPrintVisitor{}, out, i,
                          PrintMode::kHumanReadable);
      absl::Format(out, "\n");
    }

    // There doesn't seem to be a good way to generate a reproducer test when
    // the test uses a fixture (see b/241271658).
    if (!test_->uses_fixture()) {
      absl::Format(out, "%s=== Reproducer test\n\n", separator);
      absl::Format(out, "TEST(%1$s, %2$sRegression) {\n  %2$s(\n",
                   test_->suite_name(), test_->test_name());
      for (size_t i = 0; i < num_args_; ++i) {
        if (i != 0) absl::Format(out, ",\n");
        absl::Format(out, "    ");
        current_args_.Visit(ArgumentPrintVisitor{}, out, i,
                            PrintMode::kSourceCode);
      }
      absl::Format(out, "\n  );\n");
      absl::Format(out, "}\n");
    }
  } else {
    absl::Format(out, "%s=== SETUP FAILURE!\n\n", separator);
    absl::Format(out, "%s:%d: There was a problem with %s.%s.", test_->file(),
                 test_->line(), test_->suite_name(), test_->test_name());
    if (test_abort_message != nullptr) {
      absl::Format(out, "%s", *test_abort_message);
    }
  }
  absl::Format(out, "%s", separator);
}

#if defined(__linux__)

struct OldSignalHandler {
  int signum;
  struct sigaction action;
};

static FILE* signal_out;
struct FILESink {
  friend void AbslFormatFlush(FILESink*, absl::string_view v) {
    fprintf(signal_out, "%.*s", static_cast<int>(v.size()), v.data());
    fflush(signal_out);
  }
};
static FILESink signal_out_sink;

static OldSignalHandler crash_handlers[] = {{SIGILL}, {SIGFPE},  {SIGSEGV},
                                            {SIGBUS}, {SIGTRAP}, {SIGABRT}};

static OldSignalHandler termination_handlers[] = {
    {SIGHUP}, {SIGINT}, {SIGTERM}};

static void HandleCrash(int signum, siginfo_t* info, void* ucontext) {
  // Dump our info first.
  on_failure.PrintReport(&signal_out_sink);
  // The old signal handler might print important messages (e.g., strack trace)
  // to the original file descriptors,
  // therefore we restore them before calling them.
  if (IsSilenceTargetEnabled()) RestoreTargetStdoutAndStderr();
  // Find the old signal handler, if available, and call it.
  auto it =
      std::find_if(std::begin(crash_handlers), std::end(crash_handlers),
                   [signum](const auto& h) { return h.signum == signum; });
  if (it != std::end(crash_handlers) && it->action.sa_sigaction != nullptr) {
    it->action.sa_sigaction(signum, info, ucontext);
  }
}

static void HandleTermination(int, siginfo_t*, void*) {
  termination_requested.store(true, std::memory_order_relaxed);
}

static void SetNewSigAction(int signum, void (*handler)(int, siginfo_t*, void*),
                            struct sigaction* old_sigact) {
  struct sigaction new_sigact = {};
  sigemptyset(&new_sigact.sa_mask);
  new_sigact.sa_sigaction = handler;
  new_sigact.sa_flags = SA_SIGINFO;

  if (sigaction(signum, &new_sigact, old_sigact) == -1) {
    fprintf(GetStderr(), "Error installing signal handler: %s\n",
            strerror(errno));
    exit(1);
  }
}

void InstallSignalHandlers(FILE* out) {
  if (signal_out != nullptr) {
    // Already installed. Noop.
    return;
  }
  signal_out = out;

#if defined(ADDRESS_SANITIZER) || defined(MEMORY_SANITIZER)
  // An ASan failure might come without a signal.
  // Eg a divide by zero is intercepted by ASan and it terminates the process
  // after printing its output. This handler helps us print our output
  // afterwards.
  __sanitizer_set_death_callback(
      [](auto...) { on_failure.PrintReport(&signal_out_sink); });
#endif

  for (OldSignalHandler& h : crash_handlers) {
    SetNewSigAction(h.signum, &HandleCrash, &h.action);
  }

  for (OldSignalHandler& h : termination_handlers) {
    SetNewSigAction(h.signum, &HandleTermination, nullptr);
  }
}

void OnFailure::PrintFinalStatsOnDefaultSink() const {
  PrintFinalStats(&signal_out_sink);
}

void OnFailure::PrintReportOnDefaultSink() const {
  PrintReport(&signal_out_sink);
}

#else   // __linux__
// TODO(sbenzaquen): We should still install signal handlers in other systems.
void InstallSignalHandlers(FILE* out) {}

void OnFailure::PrintFinalStatsOnDefaultSink() const {}

void OnFailure::PrintReportOnDefaultSink() const {}
#endif  // __linux__

}  // namespace fuzztest::internal
