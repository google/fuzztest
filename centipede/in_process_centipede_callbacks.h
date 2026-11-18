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

  struct FailureData {
    std::array<char, kFailureBufferSize> description;
    size_t description_len = 0;
    std::array<char, kFailureBufferSize> signature;
    size_t signature_len = 0;
  };

  struct CoverageDomainConfiguration {
    bool registered = false;
    std::string name;
    uint8_t feature_id_bit_size = 0;
    uint8_t counter_bit_size = 0;
  };

  void RegisterCoverageDomain(const FuzzTestCoverageDomain& domain);
  // Calls `adapter_.FreeInput` on each of `inputs` with CFI disabled, and then
  // clears `inputs`. Needed for calls in lambdas, which are not covered by
  // disabling CFI on the enclosing function.
  void FreeAndClearInputs(std::vector<FuzzTestInputHandle>& inputs);
  // Diagnostic sink callbacks; must be async-signal-safe and thread-safe.
  void EmitError(std::string_view message);
  void EmitWarning(std::string_view message);
  void EmitFinding(std::string_view description, std::string_view signature);

  // Writes the failure into `data` and then sets `data_ready`.
  static void WriteFailureData(FailureData& data, std::atomic<bool>& data_ready,
                               std::string_view prefix,
                               std::string_view message,
                               std::string_view signature);
  // Returns true iff there is a recorded error, in which case requests
  // stopping (if not requested yet).
  bool CheckError();
  // If there is a recorded finding, waits until its data is ready. Returns true
  // iff there is a recorded finding that is not cancelled.
  bool WaitForFindingData();
  // If there is a recorded error, copies it into `batch_result` while keeping
  // the error state, and requests stopping (if not requested yet). Otherwise,
  // moves the recorded finding into `batch_result`. In both cases, clears the
  // state of any recorded finding that is not cancelled. Must be called only
  // when there is a recorded error or finding. A cancelled finding always
  // comes with a recorded error.
  void CopyErrorOrMoveFindingToBatchResult(BatchResult& batch_result);
  // Makes local writes before this call visible to finding emitters that
  // record a finding after this call.
  void SyncWithLaterFindingEmitters();

  Rng rng_;
  FuzzTestDiagnosticSink diagnostic_sink_{};
  FuzzTestAdapter adapter_{};
  bool adapter_constructed_ = false;
  std::array<CoverageDomainConfiguration, 1 << kFuzzTestCoverageDomainIdBitSize>
      coverage_domains_{};

  std::atomic<bool> in_adapter_execute_{false};

  // Error state. Once recorded, an error is never cleared.
  std::atomic<bool> has_error_{false};
  // Written only by the emitter that sets `has_error_`.
  std::unique_ptr<FailureData> error_data_;
  // Set to true when `error_data_` is fully written.
  std::atomic<bool> error_data_ready_{false};

  // Finding state. Cleared only by the thread calling `Execute()`, in
  // `CopyErrorOrMoveFindingToBatchResult()`.
  std::atomic<bool> has_finding_{false};
  // Written only by the emitter that sets `has_finding_`.
  std::unique_ptr<FailureData> finding_data_;
  // Whether the finding is cancelled for being emitted outside of adapter
  // execute, in which case an error is recorded and `finding_data_` is not
  // written. A cancelled finding is never cleared, so all later findings are
  // ignored. Written only by the emitter that sets `has_finding_`.
  bool finding_cancelled_ = false;
  // Set to true when `finding_data_` is fully written or the finding is
  // cancelled.
  std::atomic<bool> finding_data_ready_{false};

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
