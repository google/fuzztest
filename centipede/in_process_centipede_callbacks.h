// Copyright 2026 Google LLC
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

#ifndef FUZZTEST_CENTIPEDE_IN_PROCESS_CENTIPEDE_CALLBACKS_H_
#define FUZZTEST_CENTIPEDE_IN_PROCESS_CENTIPEDE_CALLBACKS_H_

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "absl/base/nullability.h"
#include "absl/types/span.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/engine_abi.h"
#include "./centipede/environment.h"
#include "./centipede/mutation_data.h"
#include "./centipede/runner_result.h"
#include "./centipede/stop.h"
#include "./common/defs.h"

namespace fuzztest::internal {

// An implementation of `CentipedeCallbacks` that invokes a
// `FuzzTestAdapterManager` directly in the current process.
class InProcessCentipedeCallbacks : public CentipedeCallbacks {
 public:
  InProcessCentipedeCallbacks(
      const Environment& env, StopCondition& stop_condition,
      const FuzzTestAdapterManager* absl_nonnull adapter_manager);
  ~InProcessCentipedeCallbacks() override;

  InProcessCentipedeCallbacks(const InProcessCentipedeCallbacks&) = delete;
  InProcessCentipedeCallbacks& operator=(const InProcessCentipedeCallbacks&) =
      delete;

  bool Execute(std::string_view binary, absl::Span<const ByteSpan> inputs,
               BatchResult& batch_result) override;

  std::vector<Mutant> Mutate(absl::Span<const MutationInputRef> inputs,
                             size_t num_mutants) override;

  size_t GetSeeds(size_t num_seeds, std::vector<ByteArray>& seeds) override;

 private:
  static constexpr size_t kFailureBufferSize = 1024;

  struct CoverageDomainConfiguration {
    bool registered = false;
    std::string name;
    uint8_t feature_id_bit_size = 0;
    uint8_t counter_bit_size = 0;
  };

  void RegisterCoverageDomain(const FuzzTestCoverageDomain& domain);
  void EmitError(std::string_view message);
  void EmitWarning(std::string_view message);
  void EmitFinding(std::string_view description, std::string_view signature);

  bool EmitFailureOutput(std::string_view prefix, std::string_view message,
                         std::string_view signature);
  void ResetBatchDiagnosticState();
  bool CheckError();
  bool CheckErrorOrFinding() {
    if (CheckError()) return true;
    return has_finding_.load(std::memory_order_relaxed);
  }
  void PopulateFailureToBatchResult(BatchResult& batch_result);

  Rng rng_;
  FuzzTestDiagnosticSink diagnostic_sink_{};
  FuzzTestAdapter adapter_{};
  bool adapter_constructed_ = false;
  std::array<CoverageDomainConfiguration, 1 << kFuzzTestCoverageDomainIdBitSize>
      coverage_domains_{};

  std::atomic<bool> in_adapter_execute_{false};
  std::atomic<bool> has_error_{false};
  std::atomic<bool> has_finding_{false};
  std::atomic<bool> has_failure_output_{false};
  std::unique_ptr<std::array<char, kFailureBufferSize>> failure_description_;
  size_t failure_description_len_ = 0;
  std::unique_ptr<std::array<char, kFailureBufferSize>> failure_signature_;
  size_t failure_signature_len_ = 0;
  // Set to true when the failure description and signature fields above are
  // fully written.
  std::atomic<bool> failure_data_ready_{false};
};

// Factory that creates `InProcessCentipedeCallbacks` instances backed by
// `adapter_manager`.
class InProcessCentipedeCallbacksFactory : public CentipedeCallbacksFactory {
 public:
  explicit InProcessCentipedeCallbacksFactory(
      const FuzzTestAdapterManager* absl_nonnull adapter_manager)
      : adapter_manager_(adapter_manager) {}

  CentipedeCallbacks* absl_nonnull create(
      const Environment& env, StopCondition& stop_condition) override {
    return new InProcessCentipedeCallbacks(env, stop_condition,
                                           adapter_manager_);
  }

  void destroy(CentipedeCallbacks* callbacks) override { delete callbacks; }

 private:
  const FuzzTestAdapterManager* absl_nonnull adapter_manager_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_CENTIPEDE_IN_PROCESS_CENTIPEDE_CALLBACKS_H_
