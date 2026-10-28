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

  enum class FailureType {
    kError,
    kFinding,
  };

  struct CoverageDomainConfiguration {
    bool registered = false;
    std::string name;
    uint8_t feature_id_bit_size = 0;
    uint8_t counter_bit_size = 0;
  };

  void RegisterCoverageDomain(const FuzzTestCoverageDomain& domain);
  // Diagnostic sink callbacks; must be async-signal-safe and thread-safe.
  void EmitError(std::string_view message, bool force = false);
  void EmitWarning(std::string_view message);
  void EmitFinding(std::string_view description, std::string_view signature);

  // Records the failure if no failure has been recorded yet. Returns true iff
  // the failure is recorded.
  bool EmitFailure(FailureType type, std::string_view prefix,
                   std::string_view message, std::string_view signature,
                   bool force = false);
  // Returns true iff there is a recorded failure. Requests stopping if the
  // failure is an error.
  bool CheckFailure();
  // Moves the recorded failure into `batch_result` and clears the failure
  // state. Must be called only when there is a recorded failure.
  void MoveFailureToBatchResult(BatchResult& batch_result);
  // Makes local writes before this call visible to failure emitters that
  // record a failure after this call.
  void SyncWithLaterFailureEmitters();

  Rng rng_;
  FuzzTestDiagnosticSink diagnostic_sink_{};
  FuzzTestAdapter adapter_{};
  bool adapter_constructed_ = false;
  std::array<CoverageDomainConfiguration, 1 << kFuzzTestCoverageDomainIdBitSize>
      coverage_domains_{};

  std::atomic<bool> in_adapter_execute_{false};
  std::atomic<bool> has_failure_{false};
  // The fields below are written only by the emitter that sets `has_failure_`.
  FailureType failure_type_ = FailureType::kError;
  std::unique_ptr<std::array<char, kFailureBufferSize>> failure_description_;
  size_t failure_description_len_ = 0;
  std::unique_ptr<std::array<char, kFailureBufferSize>> failure_signature_;
  size_t failure_signature_len_ = 0;
  // Set to true when the failure type, description and signature fields above
  // are fully written.
  std::atomic<bool> failure_data_ready_{false};

  // Needs lock-freedom to guarantee the signal-safety.
  static_assert(std::atomic<bool>::is_always_lock_free);
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
