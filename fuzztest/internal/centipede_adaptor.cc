// Copyright 2023 Google LLC
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

#include "./fuzztest/internal/centipede_adaptor.h"

#include <sys/mman.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/centipede_interface.h"
#include "./centipede/defs.h"
#include "./centipede/early_exit.h"
#include "./centipede/environment.h"
#include "./centipede/runner_interface.h"
#include "./centipede/runner_result.h"
#include "./centipede/shared_memory_blob_sequence.h"
#include "./fuzztest/internal/configuration.h"
#include "./fuzztest/internal/coverage.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/io.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/runtime.h"

namespace fuzztest::internal {
namespace {

// TODO(xinhaoyuan): Consider passing rng seeds from the engine.
std::seed_seq GetRandomSeed() {
  const size_t seed = time(nullptr) + getpid() +
                      std::hash<std::thread::id>{}(std::this_thread::get_id());
  return std::seed_seq({seed, seed >> 32});
}

centipede::Environment CreateDefaultCentipedeEnvironment() {
  centipede::Environment env;
  // Skip input timeout as we don't yet support it in FuzzTest.
  env.timeout_per_input = 0;
  // Do not limit the address space as the fuzzing engine needs a
  // lot of address space. rss_limit_mb will be used for OOM
  // detection.
  env.address_space_limit_mb = 0;
  return env;
}

centipede::Environment CreateCentipedeEnvironmentFromFuzzTestFlags(
    const Runtime& runtime, absl::string_view workdir,
    absl::string_view test_name) {
  centipede::Environment env = CreateDefaultCentipedeEnvironment();
  env.workdir = workdir;
  env.exit_on_crash = true;
  // Populating the PC table in single-process mode is not implemented.
  env.require_pc_table = false;
  if (runtime.fuzz_time_limit() != absl::InfiniteDuration()) {
    absl::FPrintF(GetStderr(), "[.] Fuzzing timeout set to: %s\n",
                  absl::FormatDuration(runtime.fuzz_time_limit()));
    env.stop_at = absl::Now() + runtime.fuzz_time_limit();
  }
  env.first_corpus_dir_output_only = true;
  if (const char* corpus_out_dir_chars = getenv("FUZZTEST_TESTSUITE_OUT_DIR")) {
    env.corpus_dir.push_back(corpus_out_dir_chars);
  } else {
    env.corpus_dir.push_back("");
  }
  if (const char* corpus_in_dir_chars = getenv("FUZZTEST_TESTSUITE_IN_DIR"))
    env.corpus_dir.push_back(corpus_in_dir_chars);
  if (const char* max_fuzzing_runs = getenv("FUZZTEST_MAX_FUZZING_RUNS")) {
    if (!absl::SimpleAtoi(max_fuzzing_runs, &env.num_runs)) {
      absl::FPrintF(GetStderr(),
                    "[!] Cannot parse env FUZZTEST_MAX_FUZZING_RUNS=%s - will "
                    "not limit fuzzing runs.\n",
                    max_fuzzing_runs);
    }
  }
  return env;
}

}  // namespace

class CentipedeAdaptorRunnerCallbacks : public centipede::RunnerCallbacks {
 public:
  CentipedeAdaptorRunnerCallbacks(Runtime& runtime,
                                  FuzzTestFuzzerImpl& fuzzer_impl,
                                  const Configuration* configuration)
      : runtime_(runtime),
        fuzzer_impl_(fuzzer_impl),
        configuration_(*configuration),
        prng_(GetRandomSeed()) {
    if (GetExecutionCoverage() == nullptr) {
      execution_coverage_ = std::make_unique<ExecutionCoverage>(
          /*counter_map=*/absl::Span<uint8_t>{});
      execution_coverage_->SetIsTracing(true);
      SetExecutionCoverage(execution_coverage_.get());
    }
  }

  bool Execute(centipede::ByteSpan input) override {
    if (auto parsed_input =
            fuzzer_impl_.TryParse({(char*)input.data(), input.size()})) {
      fuzzer_impl_.RunOneInput({*std::move(parsed_input)});
      return true;
    }
    return false;
  }

  void GetSeeds(
      std::function<void(centipede::ByteSpan)> seed_callback) override {
    std::vector<GenericDomainCorpusType> seeds =
        fuzzer_impl_.fixture_driver_->GetSeeds();
    for (const std::string& corpus_file :
         configuration_.corpus_database.GetCoverageInputsIfAny(
             fuzzer_impl_.test_.full_name())) {
      auto corpus_value = fuzzer_impl_.GetCorpusValueFromFile(corpus_file);
      if (!corpus_value) continue;
      seeds.push_back(*corpus_value);
    }
    absl::c_shuffle(seeds, prng_);
    if (seeds.empty())
      seeds.push_back(fuzzer_impl_.params_domain_->UntypedInit(prng_));
    for (const auto& seed : seeds) {
      const auto seed_serialized =
          fuzzer_impl_.params_domain_->UntypedSerializeCorpus(seed).ToString();
      seed_callback(
          {reinterpret_cast<const unsigned char*>(seed_serialized.data()),
           seed_serialized.size()});
    }
  }

  bool Mutate(
      const std::vector<centipede::MutationInputRef>& inputs,
      size_t num_mutants,
      std::function<void(centipede::ByteSpan)> new_mutant_callback) override {
    if (inputs.empty()) return false;
    SetMetadata(inputs[0].metadata);
    for (size_t i = 0; i < num_mutants; ++i) {
      const auto choice = absl::Uniform<double>(prng_, 0, 1);
      std::string mutant_data;
      constexpr double kDomainInitRatio = 0.0001;
      if (choice < kDomainInitRatio) {
        mutant_data = fuzzer_impl_.params_domain_
                          ->UntypedSerializeCorpus(
                              fuzzer_impl_.params_domain_->UntypedInit(prng_))
                          .ToString();
      } else {
        const auto& origin =
            inputs[absl::Uniform<size_t>(prng_, 0, inputs.size())].data;
        auto parsed_origin =
            fuzzer_impl_.TryParse({(const char*)origin.data(), origin.size()});
        if (!parsed_origin)
          parsed_origin = fuzzer_impl_.params_domain_->UntypedInit(prng_);
        auto mutant = FuzzTestFuzzerImpl::Input{*parsed_origin};
        fuzzer_impl_.MutateValue(mutant, prng_);
        mutant_data =
            fuzzer_impl_.params_domain_->UntypedSerializeCorpus(mutant.args)
                .ToString();
      }
      new_mutant_callback(
          {(unsigned char*)mutant_data.data(), mutant_data.size()});
    }
    return true;
  }

  ~CentipedeAdaptorRunnerCallbacks() override {
    if (GetExecutionCoverage() == execution_coverage_.get())
      SetExecutionCoverage(nullptr);
  }

 private:
  void SetMetadata(const centipede::ExecutionMetadata* metadata) {
    if (metadata == nullptr) return;
    metadata->ForEachCmpEntry([](centipede::ByteSpan a, centipede::ByteSpan b) {
      FUZZTEST_INTERNAL_CHECK(a.size() == b.size(),
                              "cmp operands must have the same size");
      const size_t size = a.size();
      if (size < kMinCmpEntrySize) return;
      if (size > kMaxCmpEntrySize) return;
      // TODO(xinhaoyuan): Consider handling integer comparison and
      // memcmp entries differently.
      GetExecutionCoverage()
          ->GetTablesOfRecentCompares()
          .GetMutable<0>()
          .Insert(a.data(), b.data(), size);
    });
  }

  // Size limits on the cmp entries to be used in mutation.
  static constexpr uint8_t kMaxCmpEntrySize = 15;
  static constexpr uint8_t kMinCmpEntrySize = 2;

  Runtime& runtime_;
  FuzzTestFuzzerImpl& fuzzer_impl_;
  const Configuration& configuration_;
  std::unique_ptr<ExecutionCoverage> execution_coverage_;
  absl::BitGen prng_;
};

namespace {

class CentipedeAdaptorEngineCallbacks : public centipede::CentipedeCallbacks {
 public:
  CentipedeAdaptorEngineCallbacks(const centipede::Environment& env,
                                  Runtime& runtime,
                                  FuzzTestFuzzerImpl& fuzzer_impl,
                                  const Configuration* configuration)
      : centipede::CentipedeCallbacks(env),
        runtime_(runtime),
        runner_callbacks_(runtime, fuzzer_impl, configuration),
        batch_result_buffer_size_(env.shmem_size_mb * 1024 * 1024),
        batch_result_buffer_(nullptr) {}

  ~CentipedeAdaptorEngineCallbacks() {
    if (batch_result_buffer_ != nullptr)
      munmap(batch_result_buffer_, batch_result_buffer_size_);
  }

  bool Execute(std::string_view binary,
               const std::vector<centipede::ByteArray>& inputs,
               centipede::BatchResult& batch_result) override {
    // Execute the test in-process.
    batch_result.ClearAndResize(inputs.size());
    size_t buffer_offset = 0;
    if (batch_result_buffer_ == nullptr) {
      // Use mmap which allocates memory on demand to reduce sanitizer overhead.
      batch_result_buffer_ = static_cast<uint8_t*>(
          mmap(nullptr, batch_result_buffer_size_, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0));
      FUZZTEST_INTERNAL_CHECK(
          batch_result_buffer_ != MAP_FAILED,
          "Cannot mmap anonymous memory for batch result buffer");
    }
    CentipedeBeginExecutionBatch();
    for (const auto& input : inputs) {
      if (runtime_.termination_requested()) break;
      if (buffer_offset >= batch_result_buffer_size_) break;
      CentipedePrepareProcessing();
      runner_callbacks_.Execute(input);
      CentipedeFinalizeProcessing();
      buffer_offset += CentipedeGetExecutionResult(
          batch_result_buffer_ + buffer_offset,
          batch_result_buffer_size_ - buffer_offset);
    }
    CentipedeEndExecutionBatch();
    if (buffer_offset > 0) {
      centipede::BlobSequence batch_result_blobseq(batch_result_buffer_,
                                                   buffer_offset);
      batch_result.Read(batch_result_blobseq);
    }
    if (runtime_.termination_requested() && !centipede::EarlyExitRequested()) {
      absl::FPrintF(GetStderr(), "[.] Early termination requested.\n");
      centipede::RequestEarlyExit(0);
    }
    return true;
  }

  size_t GetSeeds(size_t num_seeds,
                  std::vector<centipede::ByteArray>& seeds) override {
    seeds.clear();
    size_t num_avail_seeds = 0;
    runner_callbacks_.GetSeeds([&](centipede::ByteSpan seed) {
      ++num_avail_seeds;
      if (seeds.size() < num_seeds) {
        seeds.emplace_back(seed.begin(), seed.end());
      }
    });
    return num_avail_seeds;
  }

  void Mutate(const std::vector<centipede::MutationInputRef>& inputs,
              size_t num_mutants,
              std::vector<centipede::ByteArray>& mutants) override {
    mutants.clear();
    runner_callbacks_.Mutate(
        inputs, num_mutants, [&](centipede::ByteSpan mutant) {
          mutants.emplace_back(mutant.begin(), mutant.end());
        });
    if (runtime_.termination_requested() && !centipede::EarlyExitRequested()) {
      absl::FPrintF(GetStderr(), "[.] Early termination requested.\n");
      centipede::RequestEarlyExit(0);
    }
  }

 private:
  Runtime& runtime_;
  CentipedeAdaptorRunnerCallbacks runner_callbacks_;
  size_t batch_result_buffer_size_;
  uint8_t* batch_result_buffer_;
  std::unique_ptr<ExecutionCoverage> execution_coverage_;
};

class CentipedeAdaptorEngineCallbacksFactory
    : public centipede::CentipedeCallbacksFactory {
 public:
  CentipedeAdaptorEngineCallbacksFactory(Runtime& runtime,
                                         FuzzTestFuzzerImpl& fuzzer_impl,
                                         const Configuration* configuration)
      : runtime_(runtime),
        fuzzer_impl_(fuzzer_impl),
        configuration_(configuration) {}

  centipede::CentipedeCallbacks* create(
      const centipede::Environment& env) override {
    return new CentipedeAdaptorEngineCallbacks(env, runtime_, fuzzer_impl_,
                                               configuration_);
  }

  void destroy(centipede::CentipedeCallbacks* callbacks) { delete callbacks; }

 private:
  Runtime& runtime_;
  FuzzTestFuzzerImpl& fuzzer_impl_;
  const Configuration* configuration_;
};

}  // namespace

CentipedeFuzzerAdaptor::CentipedeFuzzerAdaptor(
    const FuzzTest& test, std::unique_ptr<UntypedFixtureDriver> fixture_driver)
    : test_(test), fuzzer_impl_(test_, std::move(fixture_driver)) {}

void CentipedeFuzzerAdaptor::RunInUnitTestMode(
    const Configuration& configuration) {
  // Run the unit test mode directly without using Centipede.
  fuzzer_impl_.RunInUnitTestMode(configuration);
}

int CentipedeFuzzerAdaptor::RunInFuzzingMode(
    int* argc, char*** argv, const Configuration& configuration) {
  FUZZTEST_INTERNAL_CHECK(fuzzer_impl_.fixture_driver_ != nullptr,
                          "Invalid fixture driver!");
  runtime_.SetRunMode(RunMode::kFuzz);
  runtime_.SetCurrentTest(&test_);
  if (IsSilenceTargetEnabled()) SilenceTargetStdoutAndStderr();
  runtime_.EnableReporter(&fuzzer_impl_.stats_, [] { return absl::Now(); });
  fuzzer_impl_.fixture_driver_->SetUpFuzzTest();
  // Always create a new domain input to trigger any domain setup
  // failures here. (e.g. Ineffective Filter)
  FuzzTestFuzzerImpl::PRNG prng;
  fuzzer_impl_.params_domain_->UntypedInit(prng);
  // When the CENTIPEDE_RUNNER_FLAGS env var exists, the current process is
  // considered a child process spawned by the Centipede binary as the runner,
  // and we should not run CentipedeMain in this process.
  const bool runner_mode = getenv("CENTIPEDE_RUNNER_FLAGS");
  const int result = ([&]() {
    if (runner_mode) {
      CentipedeAdaptorRunnerCallbacks runner_callbacks(runtime_, fuzzer_impl_,
                                                       &configuration);
      return centipede::RunnerMain(argc != nullptr ? *argc : 0,
                                   argv != nullptr ? *argv : nullptr,
                                   runner_callbacks);
    }
    // Centipede engine does not support replay and reproducer minimization
    // (within the single process). So use the existing fuzztest implementation.
    // This is fine because it does not require coverage instrumentation.
    if (fuzzer_impl_.ReplayInputsIfAvailable(configuration)) return 0;
    // Run as the fuzzing engine.
    if (getenv("FUZZTEST_MINIMIZE_TESTSUITE_DIR")) {
      absl::FPrintF(GetStderr(),
                    "[!] Corpus minimization is not supported in the "
                    "single-process mode. Consider using the Centipede binary "
                    "in corpus distillation mode - see centipede/README.md.");
      return 1;
    }
    TempDir workdir("/tmp/fuzztest-workdir-");
    const auto env = CreateCentipedeEnvironmentFromFuzzTestFlags(
        runtime_, workdir.path(), test_.full_name());
    CentipedeAdaptorEngineCallbacksFactory factory(runtime_, fuzzer_impl_,
                                                   &configuration);
    return centipede::CentipedeMain(env, factory);
  })();
  fuzzer_impl_.fixture_driver_->TearDownFuzzTest();
  if (result) std::exit(result);
  if (!runner_mode) {
    absl::FPrintF(GetStderr(), "\n[.] Fuzzing was terminated.\n");
    runtime_.PrintFinalStatsOnDefaultSink();
    absl::FPrintF(GetStderr(), "\n");
  }
  return 0;
}

}  // namespace fuzztest::internal

// The code below is used at very early stage of the process. Cannot use
// GetStderr().
namespace {

class CentipedeCallbacksForRunnerFlagsExtraction
    : public centipede::CentipedeCallbacks {
 public:
  using centipede::CentipedeCallbacks::CentipedeCallbacks;

  bool Execute(std::string_view binary,
               const std::vector<centipede::ByteArray>& inputs,
               centipede::BatchResult& batch_result) override {
    return false;
  }

  std::string GetRunnerFlagsContent() {
    constexpr absl::string_view kRunnerFlagPrefix = "CENTIPEDE_RUNNER_FLAGS=";
    const std::string runner_flags = ConstructRunnerFlags();
    if (!absl::StartsWith(runner_flags, kRunnerFlagPrefix)) {
      absl::FPrintF(
          stderr,
          "[!] Unexpected prefix in Centipede runner flags - returning "
          "without stripping the prefix.\n");
      return runner_flags;
    }
    return runner_flags.substr(kRunnerFlagPrefix.size());
  }
};

}  // namespace

extern "C" const char* CentipedeGetRunnerFlags() {
  if (const char* runner_flags_env = getenv("CENTIPEDE_RUNNER_FLAGS")) {
    // Runner mode. Use the existing flags.
    return strdup(runner_flags_env);
  }
  // Set the runner flags according to the FuzzTest default environment.
  const auto env = fuzztest::internal::CreateDefaultCentipedeEnvironment();
  CentipedeCallbacksForRunnerFlagsExtraction callbacks(env);
  const std::string runner_flags = callbacks.GetRunnerFlagsContent();
  absl::FPrintF(stderr, "[.] Centipede runner flags: %s\n", runner_flags);
  return strdup(runner_flags.c_str());
}
