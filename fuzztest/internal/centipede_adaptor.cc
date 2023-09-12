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

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "./centipede/runner_interface.h"
#include "./fuzztest/internal/domains/domain_base.h"
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

}  // namespace

class CentipedeAdaptorRunnerCallbacks : public centipede::RunnerCallbacks {
 public:
  CentipedeAdaptorRunnerCallbacks(Runtime& runtime,
                                  FuzzTestFuzzerImpl& fuzzer_impl)
      : runtime_(runtime), fuzzer_impl_(fuzzer_impl), prng_(GetRandomSeed()) {
    runtime_.EnableReporter(&fuzzer_impl_.stats_, [] { return absl::Now(); });
    if (IsSilenceTargetEnabled()) SilenceTargetStdoutAndStderr();
    FUZZTEST_INTERNAL_CHECK(fuzzer_impl_.fixture_driver_ != nullptr,
                            "Invalid fixture driver!");
    fuzzer_impl_.fixture_driver_->SetUpFuzzTest();
    // Always create a new domain input to trigger any domain setup
    // failures here. (e.g. Ineffective Filter)
    fuzzer_impl_.params_domain_->UntypedInit(prng_);
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
    FUZZTEST_INTERNAL_CHECK(fuzzer_impl_.fixture_driver_ != nullptr,
                            "Invalid fixture driver!");
    fuzzer_impl_.fixture_driver_->TearDownFuzzTest();
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
  absl::BitGen prng_;
};

CentipedeFuzzerAdaptor::CentipedeFuzzerAdaptor(
    const FuzzTest& test, std::unique_ptr<UntypedFixtureDriver> fixture_driver)
    : test_(test), fuzzer_impl_(test_, std::move(fixture_driver)) {}

void CentipedeFuzzerAdaptor::RunInUnitTestMode() {
  // Run the unit test mode directly without using Centipede.
  fuzzer_impl_.RunInUnitTestMode();
}

int CentipedeFuzzerAdaptor::RunInFuzzingMode(int* argc, char*** argv) {
  if (fuzztest::internal::GetExecutionCoverage() == nullptr) {
    auto* execution_coverage = new fuzztest::internal::ExecutionCoverage({});
    execution_coverage->SetIsTracing(true);
    fuzztest::internal::SetExecutionCoverage(execution_coverage);
  }

  runtime_.SetRunMode(RunMode::kFuzz);
  runtime_.SetCurrentTest(&test_);
  CentipedeAdaptorRunnerCallbacks runner_callback(runtime_, fuzzer_impl_);
  return centipede::RunnerMain(argc != nullptr ? *argc : 0,
                               argv != nullptr ? *argv : nullptr,
                               runner_callback);
}

}  // namespace fuzztest::internal
