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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_RUNTIME_H_
#define FUZZTEST_FUZZTEST_INTERNAL_RUNTIME_H_

#include <atomic>
#include <cstddef>
#include <cstdio>
#include <deque>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "absl/functional/function_ref.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/discrete_distribution.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzztest/domain.h"
#include "./fuzztest/internal/coverage.h"
#include "./fuzztest/internal/domain.h"
#include "./fuzztest/internal/fixture_driver.h"
#include "./fuzztest/internal/io.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/registration.h"
#include "./fuzztest/internal/seed_seq.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest {

// The mode in which we are running the fuzz tests.
enum class RunMode {
  // Run without instrumentation and coverage-guidance for a short time.
  kUnitTest,

  // Run coverage-guided fuzzing until a failure is detected or the test is
  // manually terminated.
  kFuzz
};

namespace internal {

class FuzzTestFuzzer {
 public:
  virtual ~FuzzTestFuzzer() = default;
  virtual void RunInUnitTestMode() = 0;
  // Returns fuzzing mode's exit code. Zero indicates success.
  virtual int RunInFuzzingMode(int* argc, char*** argv) = 0;
};

class FuzzTest;

using FuzzTestFuzzerFactory =
    std::function<std::unique_ptr<FuzzTestFuzzer>(const FuzzTest&)>;

class FuzzTest {
 public:
  FuzzTest(BasicTestInfo test_info, FuzzTestFuzzerFactory factory)
      : test_info_(test_info), make_(std::move(factory)) {}

  FuzzTest(const FuzzTest&) = delete;
  FuzzTest& operator=(const FuzzTest&) = delete;

  const char* suite_name() const { return test_info_.suite_name; }
  const char* test_name() const { return test_info_.test_name; }
  std::string full_name() const {
    return suite_name() + std::string(".") + test_name();
  }
  const std::vector<std::string_view>& param_names() const {
    return param_names_;
  }
  const char* file() const { return test_info_.file; }
  int line() const { return test_info_.line; }
  bool uses_fixture() const { return test_info_.uses_fixture; }
  auto make() const { return make_(*this); }

 private:
  BasicTestInfo test_info_;
  std::vector<std::string_view> param_names_;
  FuzzTestFuzzerFactory make_;
};

struct RuntimeStats {
  absl::Time start_time;
  size_t runs;
  size_t edges_covered;
  size_t total_edges;
  // Number of executed inputs that increase coverage.
  size_t useful_inputs;
};

void InstallSignalHandlers(FILE* report_out);

// Some failures are not necessarily detected by signal handlers or by
// sanitizers. For example, we could have test framework failures like
// `EXPECT_EQ` failures from GoogleTest.
// If such a failure is detected, the external system can set
// `external_failure_was_detected` to true to bubble it up.
// Note: Even though failures should happen within the code under test, they
// could be set from other threads at any moment. We make it an atomic to avoid
// a race condition.
extern std::atomic<bool> external_failure_was_detected;

// If true, fuzzing should terminate as soon as possible.
// Atomic because it is set from signal handlers.
extern std::atomic<bool> termination_requested;

extern RunMode run_mode;
extern absl::Duration fuzz_time_limit;

class OnFailure {
 public:
  void Enable(const RuntimeStats* stats, absl::Time (*clock_fn)()) {
    enabled_ = true;
    stats_ = stats;
    clock_fn_ = clock_fn;
    // In case we have not installed them yet, do so now.
    InstallSignalHandlers(GetStderr());
  }
  void Disable() { enabled_ = false; }

  struct Args {
    const GenericDomainCorpusType& corpus_value;
    UntypedDomainInterface& domain;
  };

  void SetCurrentTest(const FuzzTest* test) { test_ = test; }

  void SetCurrentArgs(Args* args) { current_args_ = args; }
  void UnsetCurrentArgs() { current_args_ = nullptr; }

  void PrintFinalStats(absl::FormatRawSink out) const;
  void PrintFinalStatsOnDefaultSink() const;
  void PrintReport(absl::FormatRawSink out) const;
  void PrintReportOnDefaultSink() const;

 private:
  void DumpReproducer(std::string_view outdir) const;

  bool enabled_ = false;
  Args* current_args_;
  const FuzzTest* test_;
  const RuntimeStats* stats_;
  absl::Time (*clock_fn_)() = nullptr;
};
extern OnFailure on_failure;
extern void (*crash_handler_hook)();

template <typename Arg, size_t I, typename Tuple>
decltype(auto) GetDomainOrArbitrary(const Tuple& t) {
  if constexpr (I < std::tuple_size_v<Tuple>) {
    return std::get<I>(t);
  } else {
    return Arbitrary<std::decay_t<Arg>>();
  }
}

class FuzzTestExternalEngineAdaptor;

class FuzzTestFuzzerImpl : public FuzzTestFuzzer {
 public:
  explicit FuzzTestFuzzerImpl(
      const FuzzTest& test,
      std::unique_ptr<UntypedFixtureDriver> fixture_driver);
  ~FuzzTestFuzzerImpl();

 private:
  // TODO(fniksic): Refactor to reduce code complexity and improve readability.
  void RunInUnitTestMode() override;

  // TODO(fniksic): Refactor to reduce code complexity and improve readability.
  int RunInFuzzingMode(int* argc, char*** argv) override;

  // Use the standard PRNG instead of absl::BitGen because Abseil doesn't
  // guarantee seed stability
  // (https://abseil.io/docs/cpp/guides/random#seed-stability).
  using PRNG = std::mt19937;
  using corpus_type = GenericDomainCorpusType;

  struct Input {
    corpus_type args;
    size_t depth = 0;
    absl::Duration run_time = absl::ZeroDuration();
  };
  struct RunResult {
    bool new_coverage;
    absl::Duration run_time;
  };

  void PopulateFromSeeds();

  bool ReplayInputsIfAvailable();

  std::optional<std::vector<corpus_type>> ReadReplayFile();

  std::optional<corpus_type> ReadReproducerToMinimize();

  std::optional<corpus_type> TryParse(std::string_view data);

  void MutateValue(Input& input, absl::BitGenRef prng);

  void UpdateCorpusDistribution();

  // Runs on `sample` and returns new coverage and run time. If there's new
  // coverage, outputs updated runtime stats. Additionally, if `write_to_file`
  // is true, tries to write the sample to a file.
  RunResult TrySample(const Input& sample, bool write_to_file = true);

  // Runs on `sample` and records it into the in-memory corpus if it finds new
  // coverage. If `write_to_file` is set, tries to write the corpus data to a
  // file when recording it. Updates the memory dictionary on new coverage, and
  // occasionally even if there is no new coverage.
  void TrySampleAndUpdateInMemoryCorpus(Input sample,
                                        bool write_to_file = true);

  void ForEachInputFile(absl::Span<const std::string> files,
                        absl::FunctionRef<void(Input&&)> consume);

  // Returns true if we're in minimization mode.
  bool MinimizeCorpusIfInMinimizationMode(absl::BitGenRef prng);

  std::vector<Input> TryReadCorpusFromFiles();

  void TryWriteCorpusFile(const Input& input);

  void InitializeCorpus(absl::BitGenRef prng);

  RunResult RunOneInput(const Input& input);

  bool ShouldStop();

  const FuzzTest& test_;
  std::unique_ptr<UntypedFixtureDriver> fixture_driver_;
  std::unique_ptr<UntypedDomainInterface> params_domain_;
  std::seed_seq seed_sequence_ = GetFromEnvOrMakeSeedSeq(std::cerr);
  ExecutionCoverage* execution_coverage_;
  CorpusCoverage corpus_coverage_;
  std::deque<Input> corpus_;
  // Corpus distribution is only used in Fuzzing mode.
  absl::discrete_distribution<> corpus_distribution_;

  std::string_view corpus_out_dir_;
  RuntimeStats stats_{};
  std::optional<size_t> runs_limit_;
  absl::Time time_limit_ = absl::InfiniteFuture();

#ifdef FUZZTEST_COMPATIBILITY_MODE
  friend class FuzzTestExternalEngineAdaptor;
#endif  // FUZZTEST_COMPATIBILITY_MODE
};

}  // namespace internal
}  // namespace fuzztest

#endif  // FUZZTEST_FUZZTEST_INTERNAL_RUNTIME_H_
