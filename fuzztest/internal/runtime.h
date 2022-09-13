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

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
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

#include "absl/random/random.h"
#include "absl/random/seed_sequences.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzztest/domain.h"
#include "./fuzztest/internal/coverage.h"
#include "./fuzztest/internal/domain.h"
#include "./fuzztest/internal/fixture_driver.h"
#include "./fuzztest/internal/io.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/polymorphic_value.h"
#include "./fuzztest/internal/registration.h"
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
  size_t corpus_size;
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

  template <typename Domain>
  struct Args {
    const corpus_type_t<Domain>& corpus_value;
    Domain& domain;
    static constexpr size_t kNumArgs =
        std::tuple_size_v<typename Domain::value_type>;
  };

  void SetCurrentTest(const FuzzTest* test) { test_ = test; }

  template <typename Domain>
  void SetCurrentArgs(Args<Domain>* args) {
    current_args_ = CurrentArgs(std::in_place, args);
    num_args_ = args->kNumArgs;
  }

  void UnsetCurrentArgs() { current_args_ = {}; }

  void PrintFinalStats(absl::FormatRawSink out) const;
  void PrintFinalStatsOnDefaultSink() const;
  void PrintReport(absl::FormatRawSink out) const;
  void PrintReportOnDefaultSink() const;

 private:
  void DumpReproducer(std::string_view outdir) const;

  struct ArgumentPrintVisitor {
    template <typename ArgWithDomain>
    void operator()(const ArgWithDomain& arg, absl::FormatRawSink out,
                    size_t index, PrintMode mode) {
      Switch<ArgWithDomain::kNumArgs>(index, [&](auto I) {
        PrintValue(ExtractInnerDomain<I>(arg.domain),
                   std::get<I>(arg.corpus_value), out, mode);
      });
    }
  };

  struct ArgumentSerializeVisitor {
    template <typename ArgWithDomain, typename DependentTest = FuzzTest>
    std::string operator()(const ArgWithDomain& arg) {
      return arg.domain.SerializeCorpus(arg.corpus_value).ToString();
    }
  };

  using CurrentArgs =
      VisitableValue<ArgumentPrintVisitor, ArgumentSerializeVisitor>;

  bool enabled_ = false;
  CurrentArgs current_args_;
  size_t num_args_;
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

// Used to capture buffer overflows more reliably. See more at use site.
//
// TODO(b/194687521): Remove this when we (or ASAN) detect overflows
// in strings.
struct ForceVector {
  operator std::string_view() const { return {value.data(), value.size()}; }
  std::vector<char> value;
};

template <typename Dest, typename Src>
decltype(auto) ForceVectorForStringView(Src&& src) {
  // We only do this when Src is a std::string. If it's a string view it is
  // handled by the string view domain itself.
  if constexpr (std::is_same_v<void(std::decay_t<Dest>, std::decay_t<Src>),
                               void(std::string_view, std::string)>) {
    return ForceVector{std::vector<char>(src.begin(), src.end())};
  } else {
    return std::forward<Src>(src);
  }
}

template <typename RegBase, typename Fixture, typename TargetFunction,
          typename = void>
class FuzzTestExternalEngineAdaptor;

template <typename RegBase, typename Fixture, typename TargetFunction,
          typename = void>
class FuzzTestFuzzerImpl;

template <typename RegBase, typename Fixture, typename BaseFixture,
          typename... Args>
class FuzzTestFuzzerImpl<
    RegBase, Fixture, void (BaseFixture::*)(Args...),
    std::enable_if_t<std::is_base_of_v<BaseFixture, Fixture>>>
    : public FuzzTestFuzzer {
 public:
  using TargetFunction = void (BaseFixture::*)(Args...);

  FuzzTestFuzzerImpl(
      const FuzzTest& test,
      std::unique_ptr<FixtureDriver<RegBase, Fixture, TargetFunction>>
          fixture_driver)
      : test_(test),
        fixture_driver_(std::move(fixture_driver)),
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
  ~FuzzTestFuzzerImpl() { on_failure.Disable(); }

  // TODO(fniksic): Refactor to reduce code complexity and improve readability.
  void RunInUnitTestMode() override {
    fixture_driver_->SetUpFuzzTest();
    [&] {
      on_failure.Enable(&stats_, [] { return absl::Now(); });
      on_failure.SetCurrentTest(&test_);

      // TODO(sbenzaquen): Currently, some infrastructure code assumes that replay
      // works in unit test mode, so we support it. However, we would like to
      // limit replaying to fuzzing mode only, where we can guarantee that only
      // a single FUZZ_TEST is selected to run. Once we make sure that no
      // existing infra tries to replay in unit test mode, we can remove this.
      if (ReplayInputsIfAvailable()) {
        // If ReplayInputs returns, it means the replay didn't crash.
        // In replay mode, we only replay.
        on_failure.Disable();
        return;
      }

      run_mode = RunMode::kUnitTest;

      PopulateFromSeeds();

      const auto time_limit = stats_.start_time + absl::Seconds(1);
      // TODO(b/242206122): Use seed_sequence() if a env_var is set.
      // We use a fixed random seed in unit-test mode to minimize
      // non-determinism on CI systems (continuous integration), which might
      // categorize the test as "flaky", and in order to avoid confusing users.
      // While this reduces the effectiveness of unit-test mode, this should be
      // mitigated by running this tests continuously in fuzzing mode as well.
      std::seed_seq golden_sequence{3, 8, 9, 9, 8, 3, 7, 8};
      PRNG prng(golden_sequence);
      Input mutation{params_domain_.Init(prng)};
      constexpr size_t max_iterations = 10000;
      for (int i = 0; i < max_iterations; ++i) {
        external_failure_was_detected.store(false, std::memory_order_relaxed);
        RunOneInput(mutation);
        if (external_failure_was_detected.load(std::memory_order_relaxed)) {
          break;
        }
        // We mutate the value, except that every num_mutations_per_value we
        // generate a new one through Init.
        constexpr size_t num_mutations_per_value = 100;
        if (i % num_mutations_per_value < num_mutations_per_value - 1) {
          MutateValue(mutation, prng);
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
      on_failure.SetCurrentTest(nullptr);
    }();
    fixture_driver_->TearDownFuzzTest();
  }

  // TODO(fniksic): Refactor to reduce code complexity and improve readability.
  int RunInFuzzingMode(int* argc, char*** argv) override {
    fixture_driver_->SetUpFuzzTest();
    const int exit_code = [&] {
      run_mode = RunMode::kFuzz;

      if (IsSilenceTargetEnabled()) SilenceTargetStdoutAndStderr();

      on_failure.Enable(&stats_, [] { return absl::Now(); });
      on_failure.SetCurrentTest(&test_);

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

      PopulateFromSeeds();

      PRNG prng(seed_sequence());

      if (InitializeCorpusAndCheckIfInMinimizationMode(prng)) {
        absl::FPrintF(
            GetStderr(),
            "[*] Selected %d corpus inputs in minimization mode - exiting.\n",
            corpus_.size());
        return 0;
      }

      FUZZTEST_INTERNAL_CHECK(
          !corpus_.empty(),
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
          absl::FPrintF(
              GetStderr(),
              "[!] Failed to parse FUZZTEST_MAX_FUZZING_RUNS as "
              "non-negative integer - will not limit fuzzing runs.\n");
        }
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
          MutateValue(mutation, prng);
          TrySample(mutation);
        }
      }

      absl::FPrintF(GetStderr(), "\n[.] Fuzzing was terminated.\n");
      on_failure.PrintFinalStatsOnDefaultSink();
      absl::FPrintF(GetStderr(), "\n");
      return 0;
    }();
    fixture_driver_->TearDownFuzzTest();
    return exit_code;
  }

 private:
  using PRNG = std::mt19937;
  using ParamsDomain =
      decltype(std::declval<FixtureDriver<RegBase, Fixture, TargetFunction>>()
                   .GetDomains());
  using corpus_type = typename ParamsDomain::corpus_type;
  struct Input {
    corpus_type args;
    size_t depth = 0;
    absl::Duration run_time = absl::ZeroDuration();
  };

  struct RunResult {
    bool new_coverage;
    absl::Duration run_time;
  };

  void PopulateFromSeeds() {
    for (auto& seed : fixture_driver_->GetSeeds()) {
      TrySample({seed}, /*save_corpus=*/false);
    }
  }

  bool ReplayInputsIfAvailable() {
    run_mode = RunMode::kFuzz;

    if (const auto replay_corpus = ReadReplayFile()) {
      for (const auto& corpus_value : *replay_corpus) {
        RunOneInput({corpus_value});
      }
      return true;
    }

    if (const auto to_minimize = ReadReproducerToMinimize()) {
      PRNG prng(seed_sequence());

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
      while (true) {
        auto copy = *to_minimize;
        for (int i = 0; i < num_mutations; ++i) {
          params_domain_.Mutate(copy, prng, true);
        }
        num_mutations = std::max(1, num_mutations - 1);
        // We compare the serialized version. Not very efficient but works for
        // now.
        if (params_domain_.SerializeCorpus(copy).ToString() ==
            original_serialized)
          continue;
        RunOneInput({std::move(copy)});
      }
    }

    return false;
  }

  std::optional<std::vector<corpus_type>> ReadReplayFile() {
    auto file_or_dir = absl::NullSafeStringView(getenv("FUZZTEST_REPLAY"));
    if (file_or_dir.empty()) return std::nullopt;
    std::vector<corpus_type> result;
    for (const auto& [path, data] :
         ReadFileOrDirectory(std::string(file_or_dir))) {
      if (auto corpus_value = TryParse(data)) {
        result.push_back(*std::move(corpus_value));
      } else {
        absl::FPrintF(GetStderr(), "[!] Invalid input file %s.\n===\n%s\n===\n",
                      path, data);
        continue;
      }
    }
    return result;
  }

  std::optional<corpus_type> ReadReproducerToMinimize() {
    auto file =
        absl::NullSafeStringView(getenv("FUZZTEST_MINIMIZE_REPRODUCER"));
    if (file.empty()) return std::nullopt;
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

  std::optional<corpus_type> TryParse(std::string_view data) {
    if (auto parsed = IRObject::FromString(data)) {
      return params_domain_.ParseCorpus(*parsed);
    }
    return std::nullopt;
  }

  void MutateValue(Input& input, PRNG& prng) {
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
      params_domain_.Mutate(input.args, prng, /* only_shrink= */ false);
    }
  }

  void UpdateCorpusDistribution() {
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

  // Runs on `sample` and records it into the corpus if it finds new coverage.
  // If `save_corpus` is set, tries to save the corpus data to a file when
  // recording it. Updates the memory dictionary on new coverage, and
  // occasionally even if there is no new coverage.
  void TrySample(const Input& sample, bool save_corpus = true) {
    auto [new_coverage, run_time] = RunOneInput(sample);
    if (execution_coverage_ != nullptr &&
        (stats_.runs % 4096 == 0 || new_coverage)) {
      params_domain_.UpdateMemoryDictionary(sample.args);
    }
    if (!new_coverage) return;
    // New coverage, update corpus and weights.
    Input sample_with_run_time = sample;
    sample_with_run_time.run_time = run_time;
    corpus_.push_back(sample_with_run_time);
    UpdateCorpusDistribution();
    if (save_corpus) TryWriteCorpusFile(sample);
    stats_.corpus_size = corpus_.size();
    stats_.edges_covered = corpus_coverage_.GetNumberOfCoveredEdges();
    const absl::Duration fuzzing_time = absl::Now() - stats_.start_time;
    const int64_t fuzzing_secs = absl::ToInt64Seconds(fuzzing_time);
    const int runs_per_sec =
        fuzzing_secs ? stats_.runs / fuzzing_secs : stats_.runs;
    absl::FPrintF(GetStderr(),
                  "[*] Corpus size: %5d | Edges covered: %6d | "
                  "Fuzzing time: %12s | Total runs:  %1.2e | Runs/secs: %5d\n",
                  stats_.corpus_size, stats_.edges_covered,
                  absl::FormatDuration(fuzzing_time), stats_.runs,
                  runs_per_sec);
  }

  struct ReadCorpusResult {
    std::vector<Input> inputs;
    bool to_minimize = false;
  };
  ReadCorpusResult TryReadCorpusFromFiles() {
    ReadCorpusResult result;
    auto inputdir =
        absl::NullSafeStringView(getenv("FUZZTEST_MINIMIZE_TESTSUITE_DIR"));
    if (!inputdir.empty()) {
      result.to_minimize = true;
    } else {
      inputdir = absl::NullSafeStringView(getenv("FUZZTEST_TESTSUITE_IN_DIR"));
    }
    if (inputdir.empty()) return result;

    int parsed_input_counter = 0;
    int invalid_input_counter = 0;
    for (const auto& [path, data] :
         ReadFileOrDirectory(std::string(inputdir))) {
      if (auto corpus_value = TryParse(data)) {
        ++parsed_input_counter;
        result.inputs.push_back(Input{*std::move(corpus_value)});
      } else {
        ++invalid_input_counter;
        absl::FPrintF(GetStderr(), "[!] Invalid input file %s.\n", path);
      }
    }
    absl::FPrintF(GetStderr(),
                  "[*] Parsed %d inputs and ignored %d inputs from the test "
                  "suite input dir.\n",
                  parsed_input_counter, invalid_input_counter);
    return result;
  }

  void TryWriteCorpusFile(const Input& input) {
    if (corpus_out_dir_.empty()) return;
    if (WriteDataToDir(params_domain_.SerializeCorpus(input.args).ToString(),
                       corpus_out_dir_)
            .empty()) {
      absl::FPrintF(GetStderr(), "[!] Failed to write corpus file.\n");
    }
  }

  // Returns true if we're in minimization mode.
  bool InitializeCorpusAndCheckIfInMinimizationMode(PRNG& prng) {
    auto read_corpus_result = TryReadCorpusFromFiles();
    // Since inputs processed earlier have the adventage of increasing coverage
    // and being kept in corpus, shuffle the input order to make it fair.
    std::shuffle(read_corpus_result.inputs.begin(),
                 read_corpus_result.inputs.end(), prng);
    for (const auto& input : read_corpus_result.inputs) {
      TrySample(input, /*save_corpus=*/read_corpus_result.to_minimize);
    }
    if (read_corpus_result.to_minimize) {
      return true;
    }
    if (corpus_.empty()) {
      TrySample(Input{params_domain_.Init(prng)});
    }
    return false;
  }

  RunResult RunOneInput(const Input& input) {
    ++stats_.runs;
    bool new_coverage = false;
    absl::Duration run_time;
    ApplyIndex<sizeof...(Args)>([&](auto... I) {
      auto args = params_domain_.GetValue(input.args);
      OnFailure::Args<ParamsDomain> debug_args{input.args, params_domain_};
      on_failure.SetCurrentArgs(&debug_args);

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
      // ForceVectorForStringView is a temporary hack for realiably finding
      // buffer overflows. ASAN cannot detect small overflows in
      // std::string-s. See related bug at
      // https://bugs.llvm.org/show_bug.cgi?id=26380. As a temporary
      // workaround, we enable finding overflows by copying the contents
      // of the original string into a separate temporary heap buffer.
      // TODO(b/194687521): Remove this when we (or ASAN) detect overflows
      // in strings.
      fixture_driver_->Test(
          ForceVectorForStringView<Args>(std::get<I>(std::move(args)))...);
      fixture_driver_->TearDownIteration();
      if (execution_coverage_ != nullptr) {
        execution_coverage_->SetIsTracing(false);
      }
      run_time = absl::Now() - start;

      if (execution_coverage_ != nullptr) {
        new_coverage = corpus_coverage_.Update(execution_coverage_);
      }
      on_failure.UnsetCurrentArgs();
    });
    return {new_coverage, run_time};
  }

  bool ShouldStop() {
    if (runs_limit_.has_value() && stats_.runs >= *runs_limit_) return true;
    return termination_requested.load(std::memory_order_relaxed);
  }

  absl::SeedSeq& seed_sequence() {
    if (seed_sequence_.size() == 0) {
      seed_sequence_ = absl::MakeSeedSeq();
    }
    return seed_sequence_;
  }

  const FuzzTest& test_;
  std::unique_ptr<FixtureDriver<RegBase, Fixture, TargetFunction>>
      fixture_driver_;
  ParamsDomain params_domain_ = fixture_driver_->GetDomains();
  absl::SeedSeq seed_sequence_;
  ExecutionCoverage* execution_coverage_;
  CorpusCoverage corpus_coverage_;
  std::deque<Input> corpus_;
  // Corpus distribution is only used in Fuzzing mode.
  absl::discrete_distribution<> corpus_distribution_;

  std::string_view corpus_out_dir_;
  RuntimeStats stats_{};
  std::optional<size_t> runs_limit_;

#ifdef FUZZTEST_COMPATIBILITY_MODE
  friend class FuzzTestExternalEngineAdaptor<RegBase, Fixture, TargetFunction>;
#endif  // FUZZTEST_COMPATIBILITY_MODE
};

}  // namespace internal
}  // namespace fuzztest

#endif  // FUZZTEST_FUZZTEST_INTERNAL_RUNTIME_H_
