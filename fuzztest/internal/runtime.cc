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
#include <cerrno>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <utility>
#include <vector>

#include "absl/functional/function_ref.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/discrete_distribution.h"
#include "absl/random/random.h"
#include "absl/status/status.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzztest/internal/coverage.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/fixture_driver.h"
#include "./fuzztest/internal/io.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/type_support.h"

#ifdef ADDRESS_SANITIZER
#include <sanitizer/asan_interface.h>
#endif

#ifndef TRAP_PERF
inline constexpr int TRAP_PERF = 6;
#endif

namespace fuzztest::internal {

void (*crash_handler_hook)();

void Runtime::DumpReproducer(std::string_view outdir) const {
  const std::string content =
      current_args_->domain.UntypedSerializeCorpus(current_args_->corpus_value)
          .ToString();
  const std::string filename = WriteDataToDir(content, outdir);

  if (filename.empty()) {
    absl::FPrintF(GetStderr(), "[!] Failed to write reproducer file.\n");
  } else {
    absl::FPrintF(GetStderr(), "[*] Reproducer file written to: %s\n",
                  filename);
  }
}

void Runtime::PrintFinalStats(absl::FormatRawSink out) const {
  const std::string separator = '\n' + std::string(65, '=') + '\n';
  absl::Format(out, "%s=== Fuzzing stats\n\n", separator);

  const absl::Duration fuzzing_time = clock_fn_() - stats_->start_time;
  absl::Format(out, "Elapsed time: %s\n", absl::FormatDuration(fuzzing_time));
  absl::Format(out, "Total runs: %d\n", stats_->runs);
  absl::Format(out, "Edges covered: %d\n", stats_->edges_covered);
  absl::Format(out, "Total edges: %d\n", stats_->total_edges);
  absl::Format(out, "Corpus size: %d\n", stats_->useful_inputs);
  absl::Format(out, "Max stack used: %d\n", stats_->max_stack_used);
}

void Runtime::PrintReport(absl::FormatRawSink out) const {
  // We don't want to try and print a fuzz report when we are not running a fuzz
  // test, even if we got a crash.
  if (!reporter_enabled_) return;

  if (auto* coverage = GetExecutionCoverage()) {
    // Turn off tracing to avoid having the report trigger more problems during
    // tracing, potentially leading to stack overflow.
    coverage->SetIsTracing(false);
  }

  if (crash_handler_hook) crash_handler_hook();

  // First, lets try to dump the reproducer if requested.
  if (current_args_ != nullptr) {
    const char* outdir = getenv("FUZZTEST_REPRODUCERS_OUT_DIR");
    if (outdir != nullptr && outdir[0]) {
      DumpReproducer(outdir);
    }
  }

  if (run_mode() != RunMode::kUnitTest) {
    PrintFinalStats(out);
  }

  const std::string separator = '\n' + std::string(65, '=') + '\n';

  if (current_args_ != nullptr) {
    absl::Format(out, "%s=== BUG FOUND!\n\n", separator);
    absl::Format(out, "%s:%d: Counterexample found for %s.%s.\n",
                 current_test_->file(), current_test_->line(),
                 current_test_->suite_name(), current_test_->test_name());
    absl::Format(out, "The test fails with input:\n");
    const int num_args = current_args_->domain.UntypedPrintCorpusValue(
        current_args_->corpus_value, out, PrintMode::kHumanReadable, -1);

    for (size_t i = 0; i < num_args; ++i) {
      absl::Format(out, "argument %d: ", i);
      current_args_->domain.UntypedPrintCorpusValue(
          current_args_->corpus_value, out, PrintMode::kHumanReadable, i);
      absl::Format(out, "\n");
    }

    // There doesn't seem to be a good way to generate a reproducer test when
    // the test uses a fixture (see b/241271658).
    if (!current_test_->uses_fixture()) {
      absl::Format(out, "%s=== Reproducer test\n\n", separator);
      absl::Format(out, "TEST(%1$s, %2$sRegression) {\n  %2$s(\n",
                   current_test_->suite_name(), current_test_->test_name());
      for (size_t i = 0; i < num_args; ++i) {
        if (i != 0) absl::Format(out, ",\n");
        absl::Format(out, "    ");
        current_args_->domain.UntypedPrintCorpusValue(
            current_args_->corpus_value, out, PrintMode::kSourceCode, i);
      }
      absl::Format(out, "\n  );\n");
      absl::Format(out, "}\n");
    }
  } else {
    absl::Format(out, "%s=== SETUP FAILURE!\n\n", separator);
    absl::Format(out, "%s:%d: There was a problem with %s.%s.",
                 current_test_->file(), current_test_->line(),
                 current_test_->suite_name(), current_test_->test_name());
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
  // Find the old signal handler.
  auto it =
      std::find_if(std::begin(crash_handlers), std::end(crash_handlers),
                   [signum](const auto& h) { return h.signum == signum; });
  auto old_handler =
      it != std::end(crash_handlers) ? it->action.sa_sigaction : nullptr;
  // SIGTRAP generated by perf_event_open(sigtrap=1) may be used by
  // debugging/analysis tools, so don't consider these as a crash.
  if (!old_handler || signum != SIGTRAP ||
      (info->si_code != TRAP_PERF && info->si_code != SI_TIMER)) {
    // Dump our info first.
    Runtime::instance().PrintReport(&signal_out_sink);
    // The old signal handler might print important messages (e.g., strack
    // trace) to the original file descriptors, therefore we restore them before
    // calling them.
    if (IsSilenceTargetEnabled()) RestoreTargetStdoutAndStderr();
  }
  // Call the old signal handler, if available.
  if (old_handler != nullptr) {
    old_handler(signum, info, ucontext);
  }
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

#if defined(ADDRESS_SANITIZER) || defined(MEMORY_SANITIZER)
  // An ASan failure might come without a signal.
  // Eg a divide by zero is intercepted by ASan and it terminates the process
  // after printing its output. This handler helps us print our output
  // afterwards.
  __sanitizer_set_death_callback(
      [](auto...) { Runtime::instance().PrintReport(&signal_out_sink); });
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

std::optional<corpus_type> FuzzTestFuzzerImpl::TryParse(
    absl::string_view data) {
  auto ir_value = IRObject::FromString(data);
  if (!ir_value) {
    absl::FPrintF(GetStderr(), "[!] Unexpected file format.\n");
    return std::nullopt;
  }
  auto corpus_value = params_domain_->UntypedParseCorpus(*ir_value);
  if (!corpus_value) {
    absl::FPrintF(GetStderr(), "[!] Unexpected intermediate representation.\n");
    return std::nullopt;
  }

  absl::Status is_valid =
      params_domain_->UntypedValidateCorpusValue(*corpus_value);
  if (!is_valid.ok()) {
    absl::FPrintF(GetStderr(), "[!] Invalid corpus value: %s\n",
                  is_valid.ToString());
    return std::nullopt;
  }
  return corpus_value;
}

bool FuzzTestFuzzerImpl::ReplayInputsIfAvailable() {
  runtime_.SetRunMode(RunMode::kFuzz);

  if (const auto file_paths = GetFilesToReplay()) {
    for (const std::string& path : *file_paths) {
      const auto content = ReadFile(path);
      if (!content) {
        absl::FPrintF(GetStderr(),
                      "[!] Failed to read FUZZTEST_REPLAY file or directory "
                      "(might be empty): %s\n",
                      path);
        continue;
      }
      auto corpus_value = TryParse(*content);
      if (!corpus_value) {
        absl::FPrintF(GetStderr(),
                      "[!] Skipping invalid input file %s.\n===\n%s\n===\n",
                      path, *content);
        continue;
      }
      absl::FPrintF(GetStderr(), "[.] Replaying %s\n", path);
      RunOneInput({*corpus_value});
    }
    return true;
  }

  if (const auto to_minimize = ReadReproducerToMinimize()) {
    absl::FPrintF(GetStderr(),
                  "[!] Looking for smaller mutations indefinitely: please "
                  "terminate the process manually (Ctrl-C) after some time.\n");

    PRNG prng(seed_sequence_);

    const auto original_serialized =
        params_domain_->UntypedSerializeCorpus(*to_minimize).ToString();

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
        params_domain_->UntypedMutate(copy, prng, true);
      }
      num_mutations = std::max(1, num_mutations - 1);
      // We compare the serialized version. Not very efficient but works for
      // now.
      if (params_domain_->UntypedSerializeCorpus(copy).ToString() ==
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
  return files;
}

std::optional<corpus_type> FuzzTestFuzzerImpl::ReadReproducerToMinimize() {
  auto file = absl::NullSafeStringView(getenv("FUZZTEST_MINIMIZE_REPRODUCER"));
  if (file.empty()) return std::nullopt;

  absl::FPrintF(GetStderr(), "[*] Minimizing reproducer: %s\n", file);

  auto data = ReadFile(std::string(file));

  if (!data) {
    FUZZTEST_INTERNAL_CHECK(false, "Failed to read minimizer file!");
  }

  auto res = TryParse(*data);
  if (!res) {
    absl::FPrintF(GetStderr(), "[!] Invalid input file %s.\n===\n%s\n===\n",
                  file, *data);
    FUZZTEST_INTERNAL_CHECK(false, "Failed to read minimizer file!");
  }
  return res;
}

void FuzzTestFuzzerImpl::MutateValue(Input& input, absl::BitGenRef prng) {
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
    params_domain_->UntypedMutate(input.args, prng, /* only_shrink= */ false);
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
    params_domain_->UntypedUpdateMemoryDictionary(sample.args);
  }
  if (!new_coverage) return;
  // New coverage, update corpus and weights.
  sample.run_time = run_time;
  corpus_.push_back(std::move(sample));
  UpdateCorpusDistribution();
}

void FuzzTestFuzzerImpl::ForEachInputFile(
    absl::Span<const std::string> files,
    absl::FunctionRef<void(Input&&)> consume) {
  int parsed_input_counter = 0;
  int invalid_input_counter = 0;
  for (const auto& path : files) {
    std::optional<std::string> data = ReadFile(path);
    if (!data) continue;
    if (auto corpus_value = TryParse(*data)) {
      ++parsed_input_counter;
      consume(Input{*std::move(corpus_value)});
    } else {
      ++invalid_input_counter;
      absl::FPrintF(GetStderr(), "[!] Invalid input file %s.\n", path);
    }
  }
  absl::FPrintF(GetStderr(),
                "[*] Parsed %d inputs and ignored %d inputs from the test "
                "suite input dir.\n",
                parsed_input_counter, invalid_input_counter);
}

bool FuzzTestFuzzerImpl::MinimizeCorpusIfInMinimizationMode(
    absl::BitGenRef prng) {
  auto inputdir =
      absl::NullSafeStringView(getenv("FUZZTEST_MINIMIZE_TESTSUITE_DIR"));
  if (inputdir.empty()) return false;
  std::vector<std::string> files = ListDirectory(std::string(inputdir));
  // Shuffle to potentially improve previously minimized corpus.
  std::shuffle(files.begin(), files.end(), prng);
  ForEachInputFile(files, [this](Input&& input) {
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
  ForEachInputFile(
      files, [&inputs](Input&& input) { inputs.push_back(std::move(input)); });
  return inputs;
}

void FuzzTestFuzzerImpl::TryWriteCorpusFile(const Input& input) {
  if (corpus_out_dir_.empty()) return;
  if (WriteDataToDir(
          params_domain_->UntypedSerializeCorpus(input.args).ToString(),
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
    TrySampleAndUpdateInMemoryCorpus(Input{params_domain_->UntypedInit(prng)});
  }
}

bool FuzzTestFuzzerImpl::ShouldStop() {
  if (runs_limit_.has_value() && stats_.runs >= *runs_limit_) return true;
  if (time_limit_ != absl::InfiniteFuture() && absl::Now() > time_limit_)
    return true;
  return runtime_.termination_requested();
}

void FuzzTestFuzzerImpl::PopulateFromSeeds() {
  for (const auto& seed : fixture_driver_->GetSeeds()) {
    TrySampleAndUpdateInMemoryCorpus(Input{seed},
                                     /*write_to_file=*/false);
  }
}

void FuzzTestFuzzerImpl::RunInUnitTestMode() {
  fixture_driver_->SetUpFuzzTest();
  [&] {
    runtime_.EnableReporter(&stats_, [] { return absl::Now(); });
    runtime_.SetCurrentTest(&test_);

    // TODO(sbenzaquen): Currently, some infrastructure code assumes that replay
    // works in unit test mode, so we support it. However, we would like to
    // limit replaying to fuzzing mode only, where we can guarantee that only
    // a single FUZZ_TEST is selected to run. Once we make sure that no
    // existing infra tries to replay in unit test mode, we can remove this.
    if (ReplayInputsIfAvailable()) {
      // If ReplayInputs returns, it means the replay didn't crash.
      // In replay mode, we only replay.
      runtime_.DisableReporter();
      return;
    }

    runtime_.SetRunMode(RunMode::kUnitTest);

    PopulateFromSeeds();

    auto duration = absl::Seconds(1);
    const auto fuzz_for = absl::NullSafeStringView(getenv("FUZZTEST_FUZZ_FOR"));
    if (!fuzz_for.empty()) {
      FUZZTEST_INTERNAL_CHECK(
          absl::ParseDuration(fuzz_for, &duration),
          "Could not parse duration in FUZZTEST_FUZZ_FOR=", fuzz_for);
    }
    const auto time_limit = stats_.start_time + duration;
    PRNG prng(seed_sequence_);
    Input mutation{params_domain_->UntypedInit(prng)};
    constexpr size_t max_iterations = 10000;
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
        MutateValue(mutation, prng);
      } else {
        mutation.args = params_domain_->UntypedInit(prng);
      }

      if (absl::Now() > time_limit) {
        // Break the test after 1 second of running to avoid time outs on
        // unittests when the fuzz test is doing a lot of work in a single
        // iteration.
        break;
      }
    }
    runtime_.SetCurrentTest(nullptr);
  }();
  fixture_driver_->TearDownFuzzTest();
}

FuzzTestFuzzerImpl::RunResult FuzzTestFuzzerImpl::RunOneInput(
    const Input& input) {
  ++stats_.runs;
  auto untyped_args = params_domain_->UntypedGetValue(input.args);
  Runtime::Args debug_args{input.args, *params_domain_};
  runtime_.SetCurrentArgs(&debug_args);

  // Reset and observe the coverage map and start tracing in
  // the tightest scope possible. In particular, we can't include the call
  // to GetValue in the scope as it will run user code.
  if (execution_coverage_ != nullptr) {
    execution_coverage_->ResetState();
  }
  absl::Time start = absl::Now();
  // Set tracing after absl::Now(), otherwise it will make
  // FuzzingModeTest.MinimizesDuplicatedCorpustest flaky because
  // randomness in absl::Now() being traced by cmp coverage.
  if (execution_coverage_ != nullptr) {
    execution_coverage_->SetIsTracing(true);
  }

  fixture_driver_->SetUpIteration();
  fixture_driver_->Test(std::move(untyped_args));
  fixture_driver_->TearDownIteration();
  if (execution_coverage_ != nullptr) {
    execution_coverage_->SetIsTracing(false);
  }
  const absl::Duration run_time = absl::Now() - start;

  bool new_coverage = false;
  if (execution_coverage_ != nullptr) {
    new_coverage = corpus_coverage_.Update(execution_coverage_);
    stats_.max_stack_used =
        std::max(stats_.max_stack_used, execution_coverage_->MaxStackUsed());
  }
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
      params_domain_->UntypedMutate(copy.args, prng, /* only_shrink= */ true);
    }
    // Only run it if it actually is different. Random mutations might
    // not actually change the value, or we have reached a minimum that can't be
    // minimized anymore.
    if (params_domain_
            ->UntypedSerializeCorpus(minimal_non_fatal_counterexample_->args)
            .ToString() !=
        params_domain_->UntypedSerializeCorpus(copy.args).ToString()) {
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

int FuzzTestFuzzerImpl::RunInFuzzingMode(int* /*argc*/, char*** /*argv*/) {
  fixture_driver_->SetUpFuzzTest();
  const int exit_code = [&] {
    runtime_.SetRunMode(RunMode::kFuzz);

    if (IsSilenceTargetEnabled()) SilenceTargetStdoutAndStderr();

    runtime_.EnableReporter(&stats_, [] { return absl::Now(); });
    runtime_.SetCurrentTest(&test_);

    if (ReplayInputsIfAvailable()) {
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

    PopulateFromSeeds();
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

    if (runtime_.fuzz_time_limit() != absl::InfiniteDuration()) {
      absl::FPrintF(GetStderr(), "[.] Fuzzing timeout set to: %s\n",
                    absl::FormatDuration(runtime_.fuzz_time_limit()));
      time_limit_ = stats_.start_time + runtime_.fuzz_time_limit();
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
      try_input_and_process_counterexample({params_domain_->UntypedInit(prng)});
    }

    // Fuzz corpus elements in round robin fashion.
    while (!ShouldStop()) {
      Input input_to_mutate = [&]() -> Input {
        // Try a brand new random element every now and then.
        // Otherwise, go to next corpus element in queue.
        if (stats_.runs > next_init) {
          next_init = stats_.runs + kRunsPerInit;
          return {params_domain_->UntypedInit(prng)};
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
        MutateValue(mutation, prng);
        try_input_and_process_counterexample(std::move(mutation));
      }
    }

    absl::FPrintF(GetStderr(), "\n[.] Fuzzing was terminated.\n");
    runtime_.PrintFinalStatsOnDefaultSink();
    absl::FPrintF(GetStderr(), "\n");
    return 0;
  }();
  fixture_driver_->TearDownFuzzTest();
  return exit_code;
}

}  // namespace fuzztest::internal
