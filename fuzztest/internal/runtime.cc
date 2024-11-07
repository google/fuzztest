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

#if !defined(_WIN32) && !defined(__Fuchsia__)
#define FUZZTEST_HAS_RUSAGE
#include <sys/resource.h>
#endif

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>  // NOLINT
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <thread>  // NOLINT
#include <utility>
#include <vector>

#include "absl/functional/bind_front.h"
#include "absl/functional/function_ref.h"
#include "absl/log/check.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/discrete_distribution.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzztest/internal/configuration.h"
#include "./fuzztest/internal/corpus_database.h"
#include "./fuzztest/internal/coverage.h"
#include "./fuzztest/internal/domains/mutation_metadata.h"
#include "./fuzztest/internal/fixture_driver.h"
#include "./fuzztest/internal/flag_name.h"
#include "./fuzztest/internal/io.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/printer.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/status.h"

#if defined(ADDRESS_SANITIZER) || defined(MEMORY_SANITIZER)
#define FUZZTEST_HAS_SANITIZER
#include <sanitizer/common_interface_defs.h>
#endif

#if defined(ADDRESS_SANITIZER)
#include <sanitizer/asan_interface.h>
#endif

#ifndef TRAP_PERF
inline constexpr int TRAP_PERF = 6;
#endif

namespace fuzztest::internal {
namespace {

using ::fuzztest::domain_implementor::MutationMetadata;
using ::fuzztest::domain_implementor::PrintMode;
using ::fuzztest::domain_implementor::RawSink;

constexpr size_t kValueMaxPrintLength = 2048;
constexpr absl::string_view kTrimIndicator = " ...<value too long>";
constexpr absl::string_view kReproducerDirName = "fuzztest_repro";

std::string GetFilterForCrashingInput(absl::string_view crashing_input_path) {
  std::vector<std::string> dirs = absl::StrSplit(crashing_input_path, '/');
  CHECK(dirs.size() > 2) << "Invalid crashing input path!";
  return absl::StrCat(dirs[dirs.size() - 3], "/Regression/", dirs.back());
}

// Returns a reproduction command for replaying
// `configuration.crashing_input_to_reproduce` or `reproducer_path` from a
// command line, using the `configuration.reproduction_command_template`.
std::string GetReproductionCommand(const Configuration* configuration,
                                   absl::string_view reproducer_path,
                                   absl::string_view test_name) {
  const bool is_reproducer_in_corpus_db =
      configuration && configuration->crashing_input_to_reproduce;
  CHECK(!reproducer_path.empty() || is_reproducer_in_corpus_db);
  if (!configuration || !configuration->reproduction_command_template) {
    absl::string_view reproducer =
        is_reproducer_in_corpus_db ? *configuration->crashing_input_to_reproduce
                                   : reproducer_path;
    return absl::StrFormat(
        "Replay by adding:\n\n"
        "--test_filter=%s "
        "--test_env=FUZZTEST_REPLAY=%s\n\n"
        "after `bazel test` in your original invocation.\n",
        test_name, reproducer);
  }
  const std::string command_template =
      *configuration->reproduction_command_template;
  CHECK(absl::StrContains(command_template, kTestFilterPlaceholder));
  CHECK(absl::StrContains(command_template, kExtraArgsPlaceholder));
  if (is_reproducer_in_corpus_db) {
    const std::string corpus_db = configuration->corpus_database;
    std::vector<std::string> extra_args = {absl::StrCat(
        "--test_arg=--", FUZZTEST_FLAG_PREFIX, "corpus_database=", corpus_db)};
    return absl::StrReplaceAll(
        command_template,
        {{kTestFilterPlaceholder,
          GetFilterForCrashingInput(
              *configuration->crashing_input_to_reproduce)},
         {kExtraArgsPlaceholder, absl::StrJoin(extra_args, " ")}});
  } else {
    return absl::StrReplaceAll(
        command_template,
        {{kTestFilterPlaceholder, test_name},
         {kExtraArgsPlaceholder,
          absl::StrCat("--test_env=FUZZTEST_REPLAY=", reproducer_path,
                       " --test_strategy=local --test_output=streamed")}});
  }
}

struct ReproducerDirectory {
  std::string path;
  enum class Type { kUserSpecified, kTestUndeclaredOutputs };
  Type type;
};

std::optional<ReproducerDirectory> GetReproducerDirectory() {
  auto env = absl::NullSafeStringView(getenv("FUZZTEST_REPRODUCERS_OUT_DIR"));
  if (!env.empty()) {
    return ReproducerDirectory{std::string(env),
                               ReproducerDirectory::Type::kUserSpecified};
  }
  env = absl::NullSafeStringView(getenv("TEST_UNDECLARED_OUTPUTS_DIR"));
  if (!env.empty()) {
    auto path = std::filesystem::path(std::string(env)) /
                std::string(kReproducerDirName);
    return ReproducerDirectory{
        path.string(), ReproducerDirectory::Type::kTestUndeclaredOutputs};
  }
  return std::nullopt;
}

void PrintReproductionInstructionsForUndeclaredOutputs(
    RawSink out, absl::string_view test_name,
    absl::string_view reproducer_path) {
  absl::string_view file_name = Basename(reproducer_path);
  absl::Format(out,
               "Reproducer file was dumped under"
               "TEST_UNDECLARED_OUTPUTS_DIR.\n");
  absl::Format(out,
               "Make a copy of it with:\n\n"
               "mkdir -p /tmp/%s && \\\ncp -f %s /tmp/%s/%s\n\n",
               kReproducerDirName, reproducer_path, kReproducerDirName,
               file_name);
}

absl::string_view GetSeparator() {
  return "\n================================================================="
         "\n";
}

void PrintReproducerIfRequested(RawSink out, const FuzzTest& test,
                                const Configuration* configuration,
                                std::string reproducer_path) {
  const bool is_reproducer_in_corpus_db =
      configuration && configuration->crashing_input_to_reproduce;
  if (!is_reproducer_in_corpus_db) {
    if (reproducer_path.empty()) {
      absl::FPrintF(GetStderr(), "[!] Failed to write reproducer file!\n");
      return;
    }
  }
  if (configuration && configuration->reproduction_command_template) {
    absl::Format(out, "%s=== Reproduction command\n\n", GetSeparator());
  } else {
    absl::Format(out, "%s=== Reproducer\n\n", GetSeparator());
  }
  const std::string test_name =
      absl::StrCat(test.suite_name(), ".", test.test_name());
  if (!is_reproducer_in_corpus_db) {
    auto out_dir = GetReproducerDirectory();
    switch (out_dir->type) {
      case ReproducerDirectory::Type::kUserSpecified:
        absl::Format(out, "Reproducer file was dumped at:\n%s\n",
                     reproducer_path);
        break;
      case ReproducerDirectory::Type::kTestUndeclaredOutputs:
        PrintReproductionInstructionsForUndeclaredOutputs(out, test_name,
                                                          reproducer_path);
        reproducer_path = absl::StrCat("/tmp/", kReproducerDirName, "/",
                                       Basename(reproducer_path));
        break;
    }
  }
  absl::Format(
      out, "%s\n\n",
      GetReproductionCommand(configuration, reproducer_path, test_name));
}

}  // namespace

void (*crash_handler_hook)();

Runtime::Runtime() {
  if (const char* crash_metadata_path =
          std::getenv("FUZZTEST_CRASH_METADATA_PATH");
      crash_metadata_path != nullptr) {
    RegisterCrashMetadataListener(
        [=](absl::string_view crash_type,
            absl::Span<const std::string> /*stack_frames*/) {
          WriteFile(crash_metadata_path, crash_type);
        });
  }
}

// TODO(lszekeres): Return absl::StatusOr when WriteDataToDir returns StatusOr.
std::string Runtime::DumpReproducer(absl::string_view outdir) const {
  const std::string content =
      current_args_->domain.SerializeCorpus(current_args_->corpus_value)
          .ToString();
  return WriteDataToDir(content, outdir);
}

void Runtime::PrintFinalStats(RawSink out) const {
  absl::Format(out, "%s=== Fuzzing stats\n\n", GetSeparator());

  const absl::Duration fuzzing_time = clock_fn_() - stats_->start_time;
  absl::Format(out, "Elapsed time: %s\n", absl::FormatDuration(fuzzing_time));
  absl::Format(out, "Total runs: %d\n", stats_->runs);
#ifndef FUZZTEST_USE_CENTIPEDE
  absl::Format(out, "Edges covered: %d\n", stats_->edges_covered);
  absl::Format(out, "Total edges: %d\n", stats_->total_edges);
  absl::Format(out, "Corpus size: %d\n", stats_->useful_inputs);
  absl::Format(out, "Max stack used: %d\n", stats_->max_stack_used);
#endif
}

void Runtime::PrintReport(RawSink out) const {
  // We don't want to try and print a fuzz report when we are not running a fuzz
  // test, even if we got a crash.
  if (!reporter_enabled_) return;

  if (auto* coverage = GetExecutionCoverage()) {
    // Turn off tracing to avoid having the report trigger more problems during
    // tracing, potentially leading to stack overflow.
    coverage->SetIsTracing(false);
  }

  if (crash_handler_hook) crash_handler_hook();

  for (CrashMetadataListenerRef listener : crash_metadata_listeners_) {
    listener(crash_type_.value_or("Generic crash"), {});
  }

  if (run_mode() != RunMode::kUnitTest) {
    PrintFinalStats(out);
  }

  if (current_args_ != nullptr) {
    absl::Format(out, "%s=== BUG FOUND!\n\n", GetSeparator());
    absl::Format(out, "%s:%d: Counterexample found for %s.%s.\n",
                 current_test_->file(), current_test_->line(),
                 current_test_->suite_name(), current_test_->test_name());
    auto printer = current_args_->domain.GetPrinter();
    printer.PrintFormattedAggregateValue(
        current_args_->corpus_value, out, PrintMode::kHumanReadable,
        /*prefix=*/"The test fails with input:", /*suffix=*/"\n",
        /*element_formatter=*/
        [](RawSink out, size_t idx, absl::string_view element) {
          bool trim = element.size() > kValueMaxPrintLength;
          absl::Format(out, "\nargument %d: %s%s", idx,
                       trim ? element.substr(0, kValueMaxPrintLength) : element,
                       trim ? kTrimIndicator : "");
        });

    // There doesn't seem to be a good way to generate a reproducer test when
    // the test uses a fixture (see b/241271658).
    if (!current_test_->uses_fixture()) {
      absl::Format(out, "%s=== Regression test draft\n\n", GetSeparator());

      absl::Format(out, "TEST(%1$s, %2$sRegression) {\n  %2$s(\n",
                   current_test_->suite_name(), current_test_->test_name());
      printer.PrintFormattedAggregateValue(
          current_args_->corpus_value, out, PrintMode::kSourceCode,
          /*prefix=*/"", /*suffix=*/"",
          /*element_formatter=*/
          [](RawSink out, size_t idx, absl::string_view element) {
            if (idx != 0) absl::Format(out, ",\n");
            bool trim = element.size() > kValueMaxPrintLength;
            absl::Format(
                out, "    %s%s",
                trim ? element.substr(0, kValueMaxPrintLength) : element,
                trim ? kTrimIndicator : "");
          });
      absl::Format(out, "\n  );\n");
      absl::Format(out, "}\n");

      absl::Format(out,
                   "\nPlease note that the code generated above is best effort "
                   "and is intended\n"
                   "to be used as a draft regression test.\n"
                   "For reproducing findings please rely on file based "
                   "reproduction.\n");
    }
    std::optional<ReproducerDirectory> out_dir = GetReproducerDirectory();
    const std::string reproducer_path =
        out_dir.has_value() ? DumpReproducer(out_dir->path) : "";
    PrintReproducerIfRequested(out, *current_test_, current_configuration_,
                               reproducer_path);
  } else {
    absl::Format(out, "%s=== SETUP FAILURE!\n\n", GetSeparator());
    absl::Format(out, "%s:%d: There was a problem with %s.%s.",
                 current_test_->file(), current_test_->line(),
                 current_test_->suite_name(), current_test_->test_name());
    if (test_abort_message != nullptr) {
      absl::Format(out, "%s", *test_abort_message);
    }
  }
  absl::Format(out, "%s", GetSeparator());
}

void Runtime::StartWatchdog() {
  // Centipede runner has its own watchdog.
#ifndef FUZZTEST_USE_CENTIPEDE
  auto watchdog_thread = std::thread(std::bind(&Runtime::Watchdog, this));
  while (!watchdog_thread_started) std::this_thread::yield();
  watchdog_thread.detach();
#endif
}

void Runtime::Watchdog() {
  watchdog_thread_started = true;
  while (true) {
    while (watchdog_spinlock_.test_and_set()) std::this_thread::yield();
    if (test_iteration_started_) CheckWatchdogLimits();
    watchdog_spinlock_.clear();
    absl::SleepFor(absl::Seconds(1));
  }
}

static size_t GetPeakRSSBytes() {
#ifndef FUZZTEST_HAS_RUSAGE
  return 0;
#else
  struct rusage usage = {};
  if (getrusage(RUSAGE_SELF, &usage) != 0) return 0;
  // On Linux, ru_maxrss is in KiB
  return usage.ru_maxrss * 1024;
#endif
}

void Runtime::CheckWatchdogLimits() {
  // Centipede runner has its own watchdog.
#ifndef FUZZTEST_USE_CENTIPEDE
  if (current_configuration_ == nullptr) return;
  const absl::Duration run_duration =
      clock_fn_() - current_iteration_start_time_;
  if (current_configuration_->time_limit_per_input > absl::ZeroDuration() &&
      run_duration > current_configuration_->time_limit_per_input) {
    absl::FPrintF(
        GetStderr(), "[!] Per-input timeout exceeded: %s > %s - aborting\n",
        absl::FormatDuration(run_duration),
        absl::FormatDuration(current_configuration_->time_limit_per_input));
    std::abort();
  }
  const size_t rss_usage = GetPeakRSSBytes();
  if (current_configuration_->rss_limit > 0 &&
      rss_usage > current_configuration_->rss_limit) {
    absl::FPrintF(GetStderr(),
                  "[!] RSS limit exceeded: %zu > %zu (bytes) - aborting\n",
                  rss_usage, current_configuration_->rss_limit);
    std::abort();
  }
#endif
}

void Runtime::OnTestIterationEnd() {
  test_iteration_started_ = false;
  while (watchdog_spinlock_.test_and_set()) std::this_thread::yield();
  CheckWatchdogLimits();
  watchdog_spinlock_.clear();
}

#if defined(__linux__)

struct OldSignalHandler {
  int signum;
  absl::string_view signame;
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

static OldSignalHandler crash_handlers[] = {
    {SIGILL, "SIGILL"}, {SIGFPE, "SIGFPE"},   {SIGSEGV, "SIGSEGV"},
    {SIGBUS, "SIGBUS"}, {SIGTRAP, "SIGTRAP"}, {SIGABRT, "SIGABRT"}};

static OldSignalHandler termination_handlers[] = {
    {SIGHUP, "SIGHUP"}, {SIGINT, "SIGINT"}, {SIGTERM, "SIGTERM"}};

static bool HasCustomHandler(const struct sigaction& sigaction) {
  return (sigaction.sa_flags & SA_SIGINFO) ? sigaction.sa_sigaction != nullptr
                                           : (sigaction.sa_handler != nullptr &&
                                              sigaction.sa_handler != SIG_DFL &&
                                              sigaction.sa_handler != SIG_IGN);
}

static void HandleCrash(int signum, siginfo_t* info, void* ucontext) {
  // Find the old signal handler.
  auto it =
      std::find_if(std::begin(crash_handlers), std::end(crash_handlers),
                   [signum](const auto& h) { return h.signum == signum; });
  if (it == std::end(crash_handlers)) {
    // signum should never be SIGABRT at this point, but branching on it for
    // sanity.
    absl::Format(&signal_out_sink,
                 "[!] HandleCrash called for non-crashing signal %d. This "
                 "indicates an internal bug! %s",
                 signum, signum == SIGABRT ? "Exiting" : "Aborting");
    if (signum == SIGABRT)
      std::_Exit(1);
    else
      std::abort();
  }
  Runtime& runtime = Runtime::instance();
  runtime.SetCrashTypeIfUnset(std::string(it->signame));
  const bool has_old_handler = HasCustomHandler(it->action);
  // SIGTRAP generated by perf_event_open(sigtrap=1) may be used by
  // debugging/analysis tools, so don't consider these as a crash.
  if (!has_old_handler || signum != SIGTRAP ||
      (info->si_code != TRAP_PERF && info->si_code != SI_TIMER)) {
    // Dump our info first.
    runtime.PrintReport(&signal_out_sink);
    // The old signal handler might print important messages (e.g., strack
    // trace) to the original file descriptors, therefore we restore them before
    // calling them.
    if (IsSilenceTargetEnabled()) RestoreTargetStdoutAndStderr();
  }
  if (!has_old_handler) {
    // Unblock the signal and invoke the default action if there is no old
    // handler.
    //
    // Note that we treat SIG_IGN as same as SIG_DFL at this point since we
    // already reported the crash - if we wanted to ignore the signal we should
    // return without reporting.
    sigset_t set;
    sigemptyset(&set);
    sigaddset(&set, signum);
    signal(signum, SIG_DFL);
    pthread_sigmask(SIG_UNBLOCK, &set, nullptr);
    raise(signum);
    absl::Format(&signal_out_sink,
                 "[!] The default action of crashing signal %d did not crash - "
                 "aborting",
                 signum);
    // At this point abort should be fine even if signum == SIGABRT.
    std::abort();
  }
  if (it->action.sa_flags & SA_SIGINFO) {
    it->action.sa_sigaction(signum, info, ucontext);
    return;
  }
  it->action.sa_handler(signum);
}

static void HandleTermination(int, siginfo_t*, void*) {
  Runtime::instance().SetTerminationRequested();
}

static void SetNewSigAction(int signum, void (*handler)(int, siginfo_t*, void*),
                            struct sigaction* old_sigact) {
  struct sigaction new_sigact = {};
  sigemptyset(&new_sigact.sa_mask);
  new_sigact.sa_sigaction = handler;

  // We make use of the SA_ONSTACK flag so that signal handlers are executed on
  // a separate stack. This is needed to properly handle cases where stack space
  // is limited and the delivery of a signal needs to be properly handled.
  new_sigact.sa_flags = SA_SIGINFO | SA_ONSTACK;

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

#if defined(FUZZTEST_HAS_SANITIZER)
  // An ASan failure might come without a signal.
  // Eg a divide by zero is intercepted by ASan and it terminates the process
  // after printing its output. This handler helps us print our output
  // afterwards.
  __sanitizer_set_death_callback([](auto...) {
    Runtime& runtime = Runtime::instance();
#if defined(ADDRESS_SANITIZER)
    runtime.SetCrashTypeIfUnset(__asan_get_report_description());
#else
    runtime.SetCrashTypeIfUnset("Sanitizer crash");
#endif
    runtime.PrintReport(&signal_out_sink);
  });
#endif

  for (OldSignalHandler& h : crash_handlers) {
    SetNewSigAction(h.signum, &HandleCrash, &h.action);
  }

  for (OldSignalHandler& h : termination_handlers) {
    SetNewSigAction(h.signum, &HandleTermination, nullptr);
  }
}

void Runtime::PrintFinalStatsOnDefaultSink() const {
  PrintFinalStats(&signal_out_sink);
}

void Runtime::PrintReportOnDefaultSink() const {
  PrintReport(&signal_out_sink);
}

#else   // __linux__
// TODO(sbenzaquen): We should still install signal handlers in other systems.
void InstallSignalHandlers(FILE* out) {}

void Runtime::PrintFinalStatsOnDefaultSink() const {}

void Runtime::PrintReportOnDefaultSink() const {}
#endif  // __linux__

using corpus_type = GenericDomainCorpusType;

FuzzTestFuzzerImpl::FuzzTestFuzzerImpl(
    const FuzzTest& test, std::unique_ptr<UntypedFixtureDriver> fixture_driver)
    : test_(test),
      fixture_driver_(std::move(fixture_driver)),
      params_domain_(fixture_driver_->GetDomains()),
      execution_coverage_(internal::GetExecutionCoverage()),
      corpus_coverage_(execution_coverage_ != nullptr
                           ? execution_coverage_->GetCounterMap().size()
                           : 0) {
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(fixture_driver_ != nullptr,
                                       "Invalid fixture driver!");
  stats_.start_time = absl::Now();
  const char* corpus_out_dir_chars = getenv("FUZZTEST_TESTSUITE_OUT_DIR");
  if (corpus_out_dir_chars) corpus_out_dir_ = corpus_out_dir_chars;

  std::vector<double> weights = {100.};
  corpus_distribution_ =
      absl::discrete_distribution<>(weights.begin(), weights.end());
}

FuzzTestFuzzerImpl::~FuzzTestFuzzerImpl() {
  Runtime::instance().DisableReporter();
}

absl::StatusOr<corpus_type> FuzzTestFuzzerImpl::TryParse(
    absl::string_view data) {
  auto ir_value = IRObject::FromString(data);
  if (!ir_value) {
    return absl::InvalidArgumentError("Unexpected file format");
  }
  auto corpus_value = params_domain_.ParseCorpus(*ir_value);
  if (!corpus_value) {
    return absl::InvalidArgumentError("Unexpected intermediate representation");
  }
  absl::Status is_valid = params_domain_.ValidateCorpusValue(*corpus_value);
  if (!is_valid.ok()) {
    return Prefix(is_valid, "Invalid corpus value");
  }
  return *corpus_value;
}

void FuzzTestFuzzerImpl::ReplayInput(absl::string_view file_path,
                                     std::optional<int> blob_idx,
                                     const Input& input) {
  if (blob_idx.has_value()) {
    absl::FPrintF(GetStderr(), "[.] Replaying input at index %d in %s\n",
                  *blob_idx, file_path);
  } else {
    absl::FPrintF(GetStderr(), "[.] Replaying %s\n", file_path);
  }
  RunOneInput(input);
}

bool FuzzTestFuzzerImpl::ReplayInputsIfAvailable(
    const Configuration& configuration) {
  // Crashing inputs are discovered in fuzzing mode. To increase the chance of
  // reproducing the crash, fuzzing mode should be used.
  runtime_.SetRunMode(RunMode::kFuzz);

  auto replay_input = absl::bind_front(&FuzzTestFuzzerImpl::ReplayInput, this);
  if (const auto file_paths = GetFilesToReplay()) {
    ForEachInput(*file_paths, replay_input);
    return true;
  }
  if (configuration.crashing_input_to_reproduce.has_value()) {
    configuration.preprocess_crash_reproducing();
    ForEachInput({*configuration.crashing_input_to_reproduce}, replay_input);
    return true;
  }

  if (const auto to_minimize = ReadReproducerToMinimize()) {
    absl::FPrintF(GetStderr(),
                  "[!] Looking for smaller mutations indefinitely: please "
                  "terminate the process manually (Ctrl-C) after some time.\n");

    PRNG prng(seed_sequence_);

    const auto original_serialized =
        params_domain_.SerializeCorpus(*to_minimize).ToString();

    // In minimize mode we keep mutating the given reproducer value with
    // `only_shrink=true` until we crash. We drop mutations that don't
    // actually change the value.
    // That way any crash is a smaller reproduction case.
    // We start with a lot of mutations which can speed up minimization.
    // We reduce the number of mutations if we can't find a crash, similar to
    // simulated annealing.
    int num_mutations = 20;
    int counter = 0;
    while (!ShouldStop()) {
      auto copy = *to_minimize;
      for (int i = 0; i < num_mutations; ++i) {
        params_domain_.Mutate(copy, prng, {}, true);
      }
      num_mutations = std::max(1, num_mutations - 1);
      // We compare the serialized version. Not very efficient but works for
      // now.
      if (params_domain_.SerializeCorpus(copy).ToString() ==
          original_serialized) {
        continue;
      }

      RunOneInput({std::move(copy)});

      counter++;
      if (counter == 100000) {
        absl::FPrintF(GetStderr(), ".");
        counter = 0;
      }
    }
    std::exit(130);  // Exit code termination.
  }

  return false;
}

std::optional<std::vector<std::string>> FuzzTestFuzzerImpl::GetFilesToReplay() {
  auto file_or_dir = absl::NullSafeStringView(getenv("FUZZTEST_REPLAY"));
  if (file_or_dir.empty()) return std::nullopt;
  // Try as a directory path first.
  std::vector<std::string> files = ListDirectory(std::string(file_or_dir));
  // If not, consider it a file path.
  if (files.empty()) {
    files.push_back(std::string(file_or_dir));
  }
  std::sort(files.begin(), files.end());
  return files;
}

std::optional<corpus_type> FuzzTestFuzzerImpl::ReadReproducerToMinimize() {
  auto file = absl::NullSafeStringView(getenv("FUZZTEST_MINIMIZE_REPRODUCER"));
  if (file.empty()) return std::nullopt;

  absl::FPrintF(GetStderr(), "[*] Minimizing reproducer: %s\n", file);

  std::optional<corpus_type> reproducer;
  ForEachInput({std::string(file)},
               [&](absl::string_view, std::optional<int>, Input input) {
                 FUZZTEST_INTERNAL_CHECK(!reproducer.has_value(),
                                         "Multiple inputs found in ", file);
                 reproducer = std::move(input.args);
               });
  FUZZTEST_INTERNAL_CHECK(reproducer.has_value(),
                          "Failed to read minimizer file!");
  return *reproducer;
}

void FuzzTestFuzzerImpl::MutateValue(Input& input, absl::BitGenRef prng,
                                     const MutationMetadata& metadata) {
  // Do a random number of mutations on the value at once, skewed
  // towards 1 and decreasing probability as we go up.
  // Doing multiple smaller mutations at once allows reaching states that
  // require larger mutations.
  // The current implementation with a Poisson distribution has
  // probabilities:
  // - 1 mutation:  0.368
  // - 2 mutations: 0.368
  // - 3 mutations: 0.184
  // - 4 mutations: 0.061
  // - 5 mutations: 0.015
  // - 6 mutations: 0.003
  // ...
  // The distribution and parameters have not been benchmarked or
  // optimized in any significant way.
  for (int mutations_at_once = absl::Poisson<int>(prng) + 1;
       mutations_at_once > 0; --mutations_at_once) {
    params_domain_.Mutate(input.args, prng, metadata, /*only_shrink=*/false);
  }
}

void FuzzTestFuzzerImpl::UpdateCorpusDistribution() {
  std::vector<double> weights(corpus_.size());
  absl::Duration average_time = absl::ZeroDuration();
  for (const Input& i : corpus_) {
    average_time += i.run_time;
  }
  average_time /= corpus_.size();
  // Prefer faster inputs than slower inputs, the maximum bias
  // is 30x. These weights are dynamic and won't make slow-but-interesting
  // inputs neglected: As more and more "slow but touched new coverage"
  // inputs come in, the average execution time will be larger and slow input
  // will get higher weights.
  for (size_t i = 0; i < corpus_.size(); ++i) {
    weights[i] = 100;
    if (corpus_[i].run_time > average_time * 10)
      weights[i] = 10;
    else if (corpus_[i].run_time > average_time * 4)
      weights[i] = 25;
    else if (corpus_[i].run_time > average_time * 2)
      weights[i] = 50;
    else if (corpus_[i].run_time * 3 > average_time * 4)
      weights[i] = 75;
    else if (corpus_[i].run_time * 4 < average_time)
      weights[i] = 300;
    else if (corpus_[i].run_time * 3 < average_time)
      weights[i] = 200;
    else if (corpus_[i].run_time * 2 < average_time)
      weights[i] = 150;
  }
  corpus_distribution_ =
      absl::discrete_distribution<>(weights.begin(), weights.end());
}

FuzzTestFuzzerImpl::RunResult FuzzTestFuzzerImpl::TrySample(
    const Input& sample, bool write_to_file) {
  RunResult run_result = RunOneInput(sample);
  if (runtime_.external_failure_detected()) {
    // We detected a non fatal failure. Record it separately to minimize it
    // locally.
    minimal_non_fatal_counterexample_ = sample;
  }
  if (!run_result.new_coverage) return run_result;

  if (write_to_file) TryWriteCorpusFile(sample);
  ++stats_.useful_inputs;
  stats_.edges_covered = corpus_coverage_.GetNumberOfCoveredEdges();
  const absl::Duration fuzzing_time = absl::Now() - stats_.start_time;
  const int runs_per_sec =
      static_cast<int>(stats_.runs / absl::ToDoubleSeconds(fuzzing_time));
  absl::FPrintF(GetStderr(),
                "[*] Corpus size: %5d | Edges covered: %6d | "
                "Fuzzing time: %16s | Total runs:  %1.2e | Runs/secs: %5d | "
                "Max stack usage: %8d\n",
                stats_.useful_inputs, stats_.edges_covered,
                absl::FormatDuration(fuzzing_time), stats_.runs, runs_per_sec,
                stats_.max_stack_used);
  return run_result;
}

void FuzzTestFuzzerImpl::TrySampleAndUpdateInMemoryCorpus(Input sample,
                                                          bool write_to_file) {
  auto [new_coverage, run_time] = TrySample(sample, write_to_file);
  if (execution_coverage_ != nullptr &&
      (stats_.runs % 4096 == 0 || new_coverage)) {
    auto* coverage = GetExecutionCoverage();
    params_domain_.UpdateMemoryDictionary(
        sample.args,
        coverage == nullptr ? nullptr : &coverage->GetTablesOfRecentCompares());
  }
  if (!new_coverage) return;
  // New coverage, update corpus and weights.
  sample.run_time = run_time;
  corpus_.push_back(std::move(sample));
  UpdateCorpusDistribution();
}

void FuzzTestFuzzerImpl::ForEachInput(
    absl::Span<const std::string> files,
    absl::FunctionRef<void(absl::string_view, std::optional<int>, Input)>
        consume,
    absl::Duration timeout) {
  ForEachSerializedInput(
      files,
      [this, consume](absl::string_view file_path, std::optional<int> blob_idx,
                      std::string data) {
        absl::StatusOr<corpus_type> corpus_value = TryParse(data);
        if (!corpus_value.ok()) return corpus_value.status();
        consume(file_path, blob_idx, Input{*std::move(corpus_value)});
        return absl::OkStatus();
      },
      timeout);
}

bool FuzzTestFuzzerImpl::MinimizeCorpusIfInMinimizationMode(
    absl::BitGenRef prng) {
  auto inputdir =
      absl::NullSafeStringView(getenv("FUZZTEST_MINIMIZE_TESTSUITE_DIR"));
  if (inputdir.empty()) return false;
  std::vector<std::string> files = ListDirectory(std::string(inputdir));
  // Shuffle to potentially improve previously minimized corpus.
  std::shuffle(files.begin(), files.end(), prng);
  ForEachInput(files, [this](absl::string_view /*file_path*/,
                             std::optional<int> /*blob_idx*/, Input input) {
    TrySample(input, /*write_to_file=*/true);
  });
  return true;
}

std::vector<FuzzTestFuzzerImpl::Input>
FuzzTestFuzzerImpl::TryReadCorpusFromFiles() {
  std::vector<Input> inputs;
  auto inputdir = absl::NullSafeStringView(getenv("FUZZTEST_TESTSUITE_IN_DIR"));
  if (inputdir.empty()) return inputs;
  std::vector<std::string> files = ListDirectory(std::string(inputdir));
  ForEachInput(files, [&inputs](absl::string_view /*file_path*/,
                                std::optional<int> /*blob_idx*/, Input input) {
    inputs.push_back(std::move(input));
  });
  return inputs;
}

void FuzzTestFuzzerImpl::TryWriteCorpusFile(const Input& input) {
  if (corpus_out_dir_.empty()) return;
  if (WriteDataToDir(params_domain_.SerializeCorpus(input.args).ToString(),
                     corpus_out_dir_)
          .empty()) {
    absl::FPrintF(GetStderr(), "[!] Failed to write corpus file.\n");
  }
}

void FuzzTestFuzzerImpl::InitializeCorpus(absl::BitGenRef prng) {
  std::vector<Input> inputs = TryReadCorpusFromFiles();
  // Since inputs processed earlier have the adventage of increasing coverage
  // and being kept in corpus, shuffle the input order to make it fair.
  std::shuffle(inputs.begin(), inputs.end(), prng);
  for (auto& input : inputs) {
    TrySampleAndUpdateInMemoryCorpus(std::move(input),
                                     /*write_to_file=*/false);
  }
  if (corpus_.empty()) {
    TrySampleAndUpdateInMemoryCorpus(Input{params_domain_.Init(prng)});
  }
}

bool FuzzTestFuzzerImpl::ShouldStop() {
  if (runs_limit_.has_value() && stats_.runs >= *runs_limit_) return true;
  if (time_limit_ != absl::InfiniteFuture() && absl::Now() > time_limit_)
    return true;
  return runtime_.termination_requested();
}

void FuzzTestFuzzerImpl::PopulateFromSeeds(
    const std::vector<std::string>& corpus_files) {
  for (const auto& seed : fixture_driver_->GetSeeds()) {
    TrySampleAndUpdateInMemoryCorpus(
        Input{seed},
        // Dump the seed to the corpus so that it is present when the corpus is
        // used in minimization or coverage replay.
        /*write_to_file=*/true);
  }
  ForEachInput(corpus_files,
               [this](absl::string_view /*file_path*/,
                      std::optional<int> /*blob_idx*/, Input input) {
                 TrySampleAndUpdateInMemoryCorpus(
                     std::move(input),
                     // Dump the seed to the corpus so that it is present when
                     // the corpus is used in minimization or coverage replay.
                     /*write_to_file=*/true);
               });
}

size_t GetStackLimitFromEnvOrConfiguration(const Configuration& configuration) {
  size_t env_stack_limit;
  if (const char* env = getenv("FUZZTEST_STACK_LIMIT");
      (env != nullptr && absl::SimpleAtoi(env, &env_stack_limit))) {
    absl::FPrintF(
        GetStderr(),
        "[!] Stack limit is set by FUZZTEST_STACK_LIMIT env var - this is "
        "going to be deprecated soon. Consider switching to "
        "--" FUZZTEST_FLAG_PREFIX "stack_limit_kb flag.\n");
    return env_stack_limit;
  }
  return configuration.stack_limit;
}

void PopulateLimits(const Configuration& configuration,
                    ExecutionCoverage* execution_coverage) {
  // centipede_adaptor would populate the limits to Centipede.
#ifndef FUZZTEST_USE_CENTIPEDE
  // TODO(b/273276918): For now, let existing FUZZTEST_STACK_LIMIT overwrite the
  // stack limit. So that the existing targets that set the env var could still
  // work.
  if (execution_coverage)
    execution_coverage->SetStackLimit(
        GetStackLimitFromEnvOrConfiguration(configuration));
#endif
}

void FuzzTestFuzzerImpl::RunInUnitTestMode(const Configuration& configuration) {
  runtime_.SetSkippingRequested(false);
  fixture_driver_->SetUpFuzzTest();
  [&] {
    if (runtime_.skipping_requested()) {
      absl::FPrintF(GetStderr(),
                    "[.] Skipping %s per request from the test setup.\n",
                    test_.full_name());
      return;
    }
    runtime_.StartWatchdog();
    PopulateLimits(configuration, execution_coverage_);
    runtime_.EnableReporter(&stats_, [] { return absl::Now(); });
    runtime_.SetCurrentTest(&test_, &configuration);

    // TODO(sbenzaquen): Currently, some infrastructure code assumes that replay
    // works in unit test mode, so we support it. However, we would like to
    // limit replaying to fuzzing mode only, where we can guarantee that only
    // a single FUZZ_TEST is selected to run. Once we make sure that no
    // existing infra tries to replay in unit test mode, we can remove this.
    if (ReplayInputsIfAvailable(configuration)) {
      // If ReplayInputs returns, it means the replay didn't crash.
      // In replay mode, we only replay.
      runtime_.DisableReporter();
      return;
    }

    CorpusDatabase corpus_database(configuration);
    auto replay_input =
        absl::bind_front(&FuzzTestFuzzerImpl::ReplayInput, this);
    ForEachInput(corpus_database.GetRegressionInputs(test_.full_name()),
                 replay_input);
    std::vector<std::string> coverage_inputs =
        corpus_database.GetCoverageInputsIfAny(test_.full_name());
    // Replay a random subset of the coverage input until reach the timeout.
    PRNG prng(seed_sequence_);
    std::shuffle(coverage_inputs.begin(), coverage_inputs.end(), prng);
    ForEachInput(coverage_inputs, replay_input,
                 configuration.GetTimeLimitPerTest());
    runtime_.SetRunMode(RunMode::kUnitTest);

    // If crashing inputs are reported, there's no need for a smoke test.
    if (corpus_database.use_crashing_inputs()) return;

    PopulateFromSeeds(/*corpus_files=*/{});

    auto duration = absl::Seconds(1);
    const auto fuzz_for = absl::NullSafeStringView(getenv("FUZZTEST_FUZZ_FOR"));
    if (!fuzz_for.empty()) {
      FUZZTEST_INTERNAL_CHECK(
          absl::ParseDuration(fuzz_for, &duration),
          "Could not parse duration in FUZZTEST_FUZZ_FOR=", fuzz_for);
    }
    const auto time_limit = stats_.start_time + duration;
    Input mutation{params_domain_.Init(prng)};
    const size_t max_iterations = duration == absl::ZeroDuration() ? 0 : 10000;
    for (int i = 0; i < max_iterations; ++i) {
      runtime_.SetExternalFailureDetected(false);
      RunOneInput(mutation);
      if (runtime_.external_failure_detected()) {
        break;
      }
      // We mutate the value, except that every num_mutations_per_value we
      // generate a new one through Init.
      constexpr size_t num_mutations_per_value = 100;
      if (i % num_mutations_per_value < num_mutations_per_value - 1) {
        MutateValue(mutation, prng, {});
      } else {
        mutation.args = params_domain_.Init(prng);
      }

      if (absl::Now() > time_limit) {
        // Break the test after 1 second of running to avoid time outs on
        // unittests when the fuzz test is doing a lot of work in a single
        // iteration.
        break;
      }
    }
    runtime_.SetCurrentTest(nullptr, nullptr);
  }();
  fixture_driver_->TearDownFuzzTest();
}

FuzzTestFuzzerImpl::RunResult FuzzTestFuzzerImpl::RunOneInput(
    const Input& input) {
  ++stats_.runs;
  auto untyped_args = params_domain_.GetValue(input.args);
  Runtime::Args debug_args{input.args, params_domain_};
  runtime_.SetCurrentArgs(&debug_args);

  // Reset and observe the coverage map and start tracing in
  // the tightest scope possible. In particular, we can't include the call
  // to GetValue in the scope as it will run user code.
  if (execution_coverage_ != nullptr) {
    execution_coverage_->ResetState();
  }
  absl::Time start = absl::Now();
  runtime_.OnTestIterationStart(start);
  // Set tracing after absl::Now(), otherwise it will make
  // FuzzingModeTest.MinimizesDuplicatedCorpustest flaky because
  // randomness in absl::Now() being traced by cmp coverage.
  if (execution_coverage_ != nullptr) {
    execution_coverage_->SetIsTracing(true);
  }

  runtime_.SetSkippingRequested(false);
  fixture_driver_->SetUpIteration();
  if (!runtime_.skipping_requested()) {
    fixture_driver_->Test(std::move(untyped_args));
  }
  fixture_driver_->TearDownIteration();
  if (execution_coverage_ != nullptr) {
    execution_coverage_->SetIsTracing(false);
  }
  const absl::Duration run_time = absl::Now() - start;

  bool new_coverage = false;
  if (execution_coverage_ != nullptr && !runtime_.skipping_requested()) {
    new_coverage = corpus_coverage_.Update(execution_coverage_);
    stats_.max_stack_used =
        std::max(stats_.max_stack_used, execution_coverage_->MaxStackUsed());
  }

  runtime_.OnTestIterationEnd();
  runtime_.UnsetCurrentArgs();
  return {new_coverage, run_time};
}

void FuzzTestFuzzerImpl::MinimizeNonFatalFailureLocally(absl::BitGenRef prng) {
  // We try to minimize the counterexample until we reach a point where no new
  // failures are found.
  // We stop when run kMaxTriedWithoutFailure consecutive runs without finding a
  // smaller failure, but also add a time limit in case each iteration takes too
  // long.
  const absl::Time deadline =
      std::min(absl::Now() + absl::Minutes(1), time_limit_);
  int tries_without_failure = 0;
  constexpr int kMaxTriedWithoutFailure = 10000;
  while (tries_without_failure < kMaxTriedWithoutFailure &&
         absl::Now() < deadline) {
    FUZZTEST_INTERNAL_CHECK(
        minimal_non_fatal_counterexample_.has_value(),
        "Caller didn't populate minimal_non_fatal_counterexample_");
    auto copy = *minimal_non_fatal_counterexample_;
    // Mutate a random number of times, in case one is not enough to
    // reach another failure, but prefer a low number of mutations (thus Zipf).
    for (int num_mutations = absl::Zipf(prng, 10); num_mutations >= 0;
         --num_mutations) {
      params_domain_.Mutate(copy.args, prng, {}, true);
    }
    // Only run it if it actually is different. Random mutations might
    // not actually change the value, or we have reached a minimum that can't be
    // minimized anymore.
    if (params_domain_.SerializeCorpus(minimal_non_fatal_counterexample_->args)
            .ToString() !=
        params_domain_.SerializeCorpus(copy.args).ToString()) {
      runtime_.SetExternalFailureDetected(false);
      RunOneInput(copy);
      if (runtime_.external_failure_detected()) {
        // Found a smaller one, record it and reset the counter.
        minimal_non_fatal_counterexample_ = std::move(copy);
        tries_without_failure = 0;
        continue;
      }
    }
    ++tries_without_failure;
  }
}

int FuzzTestFuzzerImpl::RunInFuzzingMode(int* /*argc*/, char*** /*argv*/,
                                         const Configuration& configuration) {
  runtime_.SetSkippingRequested(false);
  fixture_driver_->SetUpFuzzTest();
  const int exit_code = [&] {
    if (runtime_.skipping_requested()) {
      absl::FPrintF(GetStderr(),
                    "[.] Skipping %s per request from the test setup.\n",
                    test_.full_name());
      return 0;
    }
    runtime_.StartWatchdog();
    PopulateLimits(configuration, execution_coverage_);
    runtime_.SetRunMode(RunMode::kFuzz);

    if (IsSilenceTargetEnabled()) SilenceTargetStdoutAndStderr();

    runtime_.EnableReporter(&stats_, [] { return absl::Now(); });
    runtime_.SetCurrentTest(&test_, &configuration);

    if (ReplayInputsIfAvailable(configuration)) {
      // If ReplayInputs returns, it means the replay didn't crash.
      // We don't want to actually run the fuzzer so exit now.
      return 0;
    }

    if (execution_coverage_ == nullptr) {
      absl::FPrintF(
          GetStderr(),
          "\n\n[!] To fuzz, please build with --config=fuzztest.\n\n\n");
      return 1;
    }

    stats_.total_edges = execution_coverage_->GetCounterMap().size();

    PRNG prng(seed_sequence_);

    if (MinimizeCorpusIfInMinimizationMode(prng)) {
      absl::FPrintF(
          GetStderr(),
          "[*] Selected %d corpus inputs in minimization mode - exiting.\n",
          stats_.useful_inputs);
      return 0;
    }

    CorpusDatabase corpus_database(configuration);
    PopulateFromSeeds(
        corpus_database.GetCoverageInputsIfAny(test_.full_name()));
    InitializeCorpus(prng);

    FUZZTEST_INTERNAL_CHECK(!corpus_.empty(),
                            "No seed input coverage registered. Test function "
                            "might be uninstrumented?");

    constexpr size_t kRunsPerInit = 32000;
    size_t next_init = kRunsPerInit;
    if (const char* max_fuzzing_runs_env =
            getenv("FUZZTEST_MAX_FUZZING_RUNS")) {
      if (size_t max_fuzzing_runs;
          absl::SimpleAtoi(max_fuzzing_runs_env, &max_fuzzing_runs)) {
        absl::FPrintF(GetStderr(), "[.] Limiting to %d fuzzing runs.\n",
                      max_fuzzing_runs);
        runs_limit_ = stats_.runs + max_fuzzing_runs;
      } else {
        absl::FPrintF(GetStderr(),
                      "[!] Failed to parse FUZZTEST_MAX_FUZZING_RUNS as "
                      "non-negative integer - will not limit fuzzing runs.\n");
      }
    }

    const auto time_limit_per_test = configuration.GetTimeLimitPerTest();
    if (time_limit_per_test != absl::InfiniteDuration()) {
      absl::FPrintF(GetStderr(), "[.] Fuzzing timeout set to: %s\n",
                    absl::FormatDuration(time_limit_per_test));
      time_limit_ = stats_.start_time + time_limit_per_test;
    }

    runtime_.SetShouldTerminateOnNonFatalFailure(false);

    auto try_input_and_process_counterexample = [&](Input input) -> void {
      TrySampleAndUpdateInMemoryCorpus(std::move(input));

      if (minimal_non_fatal_counterexample_.has_value()) {
        // We found a failure, let's minimize it here.
        MinimizeNonFatalFailureLocally(prng);
        // Once we have minimized enough, let it crash with the best sample we
        // got.
        // TODO(sbenzaquen): Consider a different approach where we don't retry
        // the failing sample to force a crash. Instead, we could store the
        // information from the first failure and generate a report manually.
        runtime_.SetShouldTerminateOnNonFatalFailure(true);
        runtime_.SetExternalFailureDetected(false);
        RunOneInput(*minimal_non_fatal_counterexample_);
      }
    };

    // First briefly try the initial values to account for seeded domains and
    // possible special values.
    constexpr int kInitialValuesToTry = 32;
    for (int i = 0; i < kInitialValuesToTry && !ShouldStop(); ++i) {
      try_input_and_process_counterexample({params_domain_.Init(prng)});
    }

    MutationMetadata mutation_metadata;
    if (auto* coverage = GetExecutionCoverage(); coverage != nullptr) {
      mutation_metadata.cmp_tables = &coverage->GetTablesOfRecentCompares();
    }
    // Fuzz corpus elements in round robin fashion.
    while (!ShouldStop()) {
      Input input_to_mutate = [&]() -> Input {
        // Try a brand new random element every now and then.
        // Otherwise, go to next corpus element in queue.
        if (stats_.runs > next_init) {
          next_init = stats_.runs + kRunsPerInit;
          return {params_domain_.Init(prng)};
        } else {
          size_t idx = static_cast<size_t>(corpus_distribution_(prng));
          FUZZTEST_INTERNAL_CHECK(0 <= idx && idx < corpus_.size(),
                                  "Corpus input weights are outdated!\n");
          return corpus_[idx];
        }
      }();
      constexpr int kMutationsPerInput = 32;
      for (int i = 0; i < kMutationsPerInput; ++i) {
        if (ShouldStop()) break;
        Input mutation = input_to_mutate;
        MutateValue(mutation, prng, mutation_metadata);
        try_input_and_process_counterexample(std::move(mutation));
      }
    }

    runtime_.SetCurrentTest(nullptr, nullptr);

    absl::FPrintF(GetStderr(), "\n[.] Fuzzing was terminated.\n");
    runtime_.PrintFinalStatsOnDefaultSink();
    absl::FPrintF(GetStderr(), "\n");
    return 0;
  }();
  fixture_driver_->TearDownFuzzTest();
  return exit_code;
}

}  // namespace fuzztest::internal
