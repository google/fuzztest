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

#include "./centipede/in_process_centipede_callbacks.h"

#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <thread>  // NOLINT: for std::this_thread
#include <type_traits>
#include <vector>

#include "absl/base/nullability.h"
#include "absl/cleanup/cleanup.h"
#include "absl/types/span.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/engine_abi.h"
#include "./centipede/environment.h"
#include "./centipede/feature.h"
#include "./centipede/mutation_data.h"
#include "./centipede/runner_result.h"
#include "./centipede/stop.h"
#include "./centipede/util.h"
#include "./common/defs.h"
#include "./common/hash.h"
#include "./common/logging.h"

namespace fuzztest::internal {
namespace {

constexpr size_t kDefaultMinSeeds = 32;
constexpr int kDefaultCrossOverLevel = 50;

constexpr std::array<std::string_view, 3> kNonFindingPrefixes = {
    "SETUP FAILURE:",
    "IGNORED FAILURE:",
    "SKIPPED TEST:",
};

inline std::string_view ToStringView(
    const FuzzTestBytesView* absl_nonnull bytes_view) {
  return {reinterpret_cast<const char*>(bytes_view->data), bytes_view->size};
}

inline std::string_view ToStringView(const std::vector<uint8_t>& bytes) {
  return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

FuzzTestBytesSink GetBytesSinkTo(std::vector<uint8_t>& bytes) {
  return {
      /*ctx=*/reinterpret_cast<FuzzTestBytesSinkCtx*>(&bytes),
      /*Emit=*/
      [](FuzzTestBytesSinkCtx* ctx, const FuzzTestBytesView* view) {
        auto* output = reinterpret_cast<std::vector<uint8_t>*>(ctx);
        output->insert(output->end(), view->data, view->data + view->size);
      },
  };
}

FuzzTestInputSink GetInputSinkTo(std::vector<FuzzTestInputHandle>& inputs) {
  return {
      /*ctx=*/reinterpret_cast<FuzzTestInputSinkCtx*>(&inputs),
      /*Emit=*/
      [](FuzzTestInputSinkCtx* ctx, FuzzTestInputHandle input) {
        auto* output = reinterpret_cast<std::vector<FuzzTestInputHandle>*>(ctx);
        output->push_back(input);
      },
  };
}

template <typename T>
constexpr T Bits(T v, size_t begin, size_t size) {
  return (v >> begin) & ((T{1} << size) - 1);
}

uint64_t TimeInUsec() {
  struct timeval tv = {};
  constexpr size_t kUsecInSec = 1000000;
  gettimeofday(&tv, nullptr);
  return tv.tv_sec * kUsecInSec + tv.tv_usec;
}

class Timer {
 public:
  uint64_t UsecSinceLast() {
    const uint64_t t = TimeInUsec();
    const uint64_t ret = t - last_time_usec_;
    last_time_usec_ = t;
    return ret;
  }

 private:
  uint64_t last_time_usec_ = TimeInUsec();
};

size_t GetPeakRSSMb() {
  struct rusage usage = {};
  if (getrusage(RUSAGE_SELF, &usage) != 0) return 0;
#ifdef __APPLE__
  // On MacOS, the unit seems to be byte according to experiment, while some
  // documents mentioned KiB. This could depend on OS variants.
  return usage.ru_maxrss >> 20;
#else   // __APPLE__
  // On Linux, ru_maxrss is in KiB.
  return usage.ru_maxrss >> 10;
#endif  // __APPLE__
}

template <size_t N, typename... Parts>
size_t CopyToBuffer(std::array<char, N>& buffer, const Parts&... parts) {
  static_assert((std::is_convertible_v<const Parts&, std::string_view> && ...));
  size_t offset = 0;
  auto append = [&](std::string_view part) {
    const size_t to_copy = std::min(part.size(), buffer.size() - offset);
    if (to_copy > 0) {
      std::memcpy(buffer.data() + offset, part.data(), to_copy);
      offset += to_copy;
    }
  };
  (append(parts), ...);
  return offset;
}

void WriteStderr(std::string_view sv) {
  while (!sv.empty()) {
    const ssize_t r = write(STDERR_FILENO, sv.data(), sv.size());
    if (r > 0) {
      sv.remove_prefix(static_cast<size_t>(r));
      continue;
    }
    if (r == -1 && errno == EINTR) continue;
    break;
  }
}

// Logging in diagnostic callbacks needs to be signal-safe and thread-safe.
template <typename... Parts>
void SignalSafeLog(const Parts&... parts) {
  static_assert((std::is_convertible_v<const Parts&, std::string_view> && ...));
  (WriteStderr(parts), ...);
  WriteStderr("\n");
  (void)fsync(STDERR_FILENO);
}

}  // namespace

InProcessCentipedeCallbacks::InProcessCentipedeCallbacks(
    const Environment& env, StopCondition& stop_condition,
    const FuzzTestAdapterManager* absl_nonnull adapter_manager)
    : CentipedeCallbacks(env, stop_condition),
      rng_(GetRandomSeed(env.seed)),
      failure_description_(
          std::make_unique<std::array<char, kFailureBufferSize>>()),
      failure_signature_(
          std::make_unique<std::array<char, kFailureBufferSize>>()) {
  FUZZTEST_CHECK(adapter_manager != nullptr)
      << "adapter_manager must not be nullptr";
  FUZZTEST_CHECK(adapter_manager->GetTestName != nullptr)
      << "GetTestName is not defined";

  diagnostic_sink_ = {
      /*ctx=*/reinterpret_cast<FuzzTestDiagnosticSinkCtx*>(this),
      /*EmitError=*/
      [](FuzzTestDiagnosticSinkCtx* ctx, const FuzzTestBytesView* message) {
        auto* self = reinterpret_cast<InProcessCentipedeCallbacks*>(ctx);
        self->EmitError(ToStringView(message));
      },
      /*EmitWarning=*/
      [](FuzzTestDiagnosticSinkCtx* ctx, const FuzzTestBytesView* message) {
        auto* self = reinterpret_cast<InProcessCentipedeCallbacks*>(ctx);
        self->EmitWarning(ToStringView(message));
      },
      /*EmitFinding=*/
      [](FuzzTestDiagnosticSinkCtx* ctx, const FuzzTestBytesView* description,
         const FuzzTestBytesView* signature) {
        auto* self = reinterpret_cast<InProcessCentipedeCallbacks*>(ctx);
        self->EmitFinding(ToStringView(description), ToStringView(signature));
      },
  };

  std::vector<uint8_t> test_name;
  const auto test_name_sink = GetBytesSinkTo(test_name);
  adapter_manager->GetTestName(adapter_manager->ctx, &test_name_sink);
  if (CheckFailure()) return;
  if (!env_.test_name.empty() && !test_name.empty()) {
    FUZZTEST_CHECK_EQ(ToStringView(test_name), env_.test_name)
        << "Adapter manager test name does not match env_.test_name";
  }

  FUZZTEST_CHECK(adapter_manager->ConstructAdapter != nullptr)
      << "ConstructAdapter is not defined";
  adapter_manager->ConstructAdapter(adapter_manager->ctx, &diagnostic_sink_,
                                    &adapter_);
  FUZZTEST_CHECK(adapter_.FreeCtx != nullptr) << "FreeCtx must be defined";
  adapter_constructed_ = true;
  if (CheckFailure()) return;

  FUZZTEST_CHECK(adapter_.SetUpCoverageDomains != nullptr)
      << "SetUpCoverageDomains must be defined";
  FUZZTEST_CHECK(adapter_.GetRandomSeedInput != nullptr)
      << "GetRandomSeedInput must be defined";
  FUZZTEST_CHECK(adapter_.Execute != nullptr) << "Execute must be defined";
  FUZZTEST_CHECK(adapter_.Mutate != nullptr) << "Mutate must be defined";
  FUZZTEST_CHECK(adapter_.SerializeInputContent != nullptr)
      << "SerializeInputContent must be defined";
  FUZZTEST_CHECK(adapter_.DeserializeInputContent != nullptr)
      << "DeserializeInputContent must be defined";
  FUZZTEST_CHECK(adapter_.FreeInput != nullptr) << "FreeInput must be defined";

  FuzzTestCoverageDomainRegistry registry = {
      /*ctx=*/reinterpret_cast<FuzzTestCoverageDomainRegistryCtx*>(this),
      /*Register=*/
      [](FuzzTestCoverageDomainRegistryCtx* ctx,
         const FuzzTestCoverageDomain* domain) {
        auto* self = reinterpret_cast<InProcessCentipedeCallbacks*>(ctx);
        self->RegisterCoverageDomain(*domain);
      },
  };
  adapter_.SetUpCoverageDomains(adapter_.ctx, &registry);
  CheckFailure();
}

InProcessCentipedeCallbacks::~InProcessCentipedeCallbacks() {
  if (adapter_constructed_) {
    adapter_.FreeCtx(adapter_.ctx);
    CheckFailure();
  }
}

void InProcessCentipedeCallbacks::RegisterCoverageDomain(
    const FuzzTestCoverageDomain& domain) {
  // Checking against `kNumDomains` is sufficient for the ABI domain ID range
  // and indexing `coverage_domains_`.
  static_assert(feature_domains::kNumDomains <=
                (1 << kFuzzTestCoverageDomainIdBitSize));
  FUZZTEST_CHECK_LT(domain.domain_id, feature_domains::kNumDomains)
      << "domain ID exceeds the number of Centipede feature domains";
  FUZZTEST_CHECK_LE(domain.feature_id_bit_size,
                    kFuzzTestCoverageFeatureIdBitSize)
      << "domain feature id bit size is too large";
  FUZZTEST_CHECK_LE(domain.counter_bit_size, kFuzzTestCoverageCounterBitSize)
      << "domain counter bit size is too large";
  FUZZTEST_CHECK(!coverage_domains_[domain.domain_id].registered)
      << "domain ID is already registered";
  coverage_domains_[domain.domain_id].registered = true;
  coverage_domains_[domain.domain_id].name = ToStringView(&domain.name);
  coverage_domains_[domain.domain_id].feature_id_bit_size =
      domain.feature_id_bit_size;
  coverage_domains_[domain.domain_id].counter_bit_size =
      domain.counter_bit_size;
}

bool InProcessCentipedeCallbacks::EmitFailure(FailureType type,
                                              std::string_view prefix,
                                              std::string_view message,
                                              std::string_view signature,
                                              bool force) {
  const bool ignored =
      !force && has_failure_.exchange(true, std::memory_order_acq_rel);
  if (!ignored) {
    failure_type_ = type;
    failure_description_len_ =
        CopyToBuffer(*failure_description_, prefix, message);
    failure_signature_len_ = CopyToBuffer(*failure_signature_, signature);
    failure_data_ready_.store(true, std::memory_order_release);
    SignalSafeLog("Emitted failure output: ", prefix, message);
  } else {
    SignalSafeLog("Ignored emitting failure output: ", prefix, message);
  }
  return !ignored;
}

void InProcessCentipedeCallbacks::EmitError(std::string_view message,
                                            bool force) {
  EmitFailure(FailureType::kError, "SETUP FAILURE: ", message,
              /*signature=*/"", force);
}

void InProcessCentipedeCallbacks::EmitWarning(std::string_view message) {
  SignalSafeLog("WARNING: InProcessCentipedeCallbacks: ", message);
}

void InProcessCentipedeCallbacks::EmitFinding(std::string_view description,
                                              std::string_view signature) {
  SignalSafeLog("EmitFinding: description: ", description,
                " signature: ", signature);
  for (std::string_view bad_prefix : kNonFindingPrefixes) {
    if (description.substr(0, bad_prefix.size()) == bad_prefix) {
      SignalSafeLog("Got bad prefix in the finding description: ", description);
      EmitError("Bad prefix in the finding description");
      return;
    }
  }
  const bool has_previous_failure =
      has_failure_.exchange(true, std::memory_order_acq_rel);
  if (has_previous_failure) {
    SignalSafeLog("Ignored emitting finding: ", description);
    return;
  }
  // Relaxed is sufficient: the acq_rel exchange above synchronizes with
  // SyncWithLaterFailureEmitters() in Execute() after clearing
  // `in_adapter_execute_`.
  if (!in_adapter_execute_.load(std::memory_order_relaxed)) {
    EmitError("Must emit finding in adapter execute", /*force=*/true);
    SignalSafeLog("Must emit finding in adapter execute");
    return;
  }
  if (EmitFailure(FailureType::kFinding, /*prefix=*/"", description, signature,
                  /*force=*/true)) {
    SignalSafeLog("Emitted finding: ", description);
  } else {
    SignalSafeLog("Ignored emitted finding UNEXPECTEDLY (FuzzTest bug!): ",
                  description);
  }
}

bool InProcessCentipedeCallbacks::CheckFailure() {
  if (!has_failure_.load(std::memory_order_acquire)) {
    return false;
  }
  while (!failure_data_ready_.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }
  if (failure_type_ == FailureType::kError &&
      !stop_condition_.StopRequested()) {
    stop_condition_.RequestStop(EXIT_FAILURE,
                                std::string_view(failure_description_->data(),
                                                 failure_description_len_));
  }
  return true;
}

void InProcessCentipedeCallbacks::MoveFailureToBatchResult(
    BatchResult& batch_result) {
  FUZZTEST_CHECK(has_failure_.load(std::memory_order_acquire))
      << "MoveFailureToBatchResult called without a recorded failure";
  batch_result.exit_code() = EXIT_FAILURE;
  while (!failure_data_ready_.load(std::memory_order_acquire)) {
    std::this_thread::yield();
  }
  batch_result.failure_description().assign(failure_description_->data(),
                                            failure_description_len_);
  const std::string_view signature(failure_signature_->data(),
                                   failure_signature_len_);
  batch_result.failure_signature() =
      signature.empty() ? Hash(batch_result.failure_description())
                        : Hash(signature);

  failure_type_ = FailureType::kError;
  failure_description_len_ = 0;
  failure_signature_len_ = 0;
  failure_data_ready_.store(false, std::memory_order_release);
  has_failure_.store(false, std::memory_order_release);
}

void InProcessCentipedeCallbacks::SyncWithLaterFailureEmitters() {
  // Use an RMW (instead of a plain load) so that it is in the modification
  // order of `has_failure_`. If it observes no failure, a later
  // `has_failure_.exchange()` in a failure emitter reads from it (or a later
  // RMW in its release sequence) and synchronizes with it.
  bool expected_no_failure = false;
  has_failure_.compare_exchange_strong(expected_no_failure, false,
                                       std::memory_order_acq_rel,
                                       std::memory_order_acquire);
}

size_t InProcessCentipedeCallbacks::GetSeeds(size_t num_seeds,
                                             std::vector<ByteArray>& seeds) {
  seeds.clear();
  if (CheckFailure()) return 0;

  std::vector<FuzzTestInputHandle> seed_handles;
  const auto input_sink = GetInputSinkTo(seed_handles);
  auto free_all_handles = [&] {
    for (FuzzTestInputHandle handle : seed_handles) {
      adapter_.FreeInput(adapter_.ctx, handle);
    }
  };

  if (adapter_.GetPresetSeedInputs != nullptr) {
    adapter_.GetPresetSeedInputs(adapter_.ctx, &input_sink);
    if (CheckFailure()) {
      free_all_handles();
      return 0;
    }
  }

  while (seed_handles.size() < kDefaultMinSeeds) {
    const size_t prev_size = seed_handles.size();
    adapter_.GetRandomSeedInput(adapter_.ctx, &input_sink);
    if (CheckFailure()) {
      free_all_handles();
      return 0;
    }
    FUZZTEST_CHECK_EQ(seed_handles.size(), prev_size + 1)
        << "GetRandomSeedInput must emit exactly one input";
  }

  const size_t num_avail_seeds = seed_handles.size();
  const size_t num_seeds_to_read = std::min(num_seeds, num_avail_seeds);
  seeds.resize(num_seeds_to_read);
  for (size_t i = 0; i < num_avail_seeds; ++i) {
    if (i < num_seeds_to_read) {
      const auto bytes_sink = GetBytesSinkTo(seeds[i]);
      adapter_.SerializeInputContent(adapter_.ctx, seed_handles[i],
                                     &bytes_sink);
    }
    adapter_.FreeInput(adapter_.ctx, seed_handles[i]);
  }
  if (CheckFailure()) {
    seeds.clear();
    return 0;
  }
  return num_avail_seeds;
}

std::vector<Mutant> InProcessCentipedeCallbacks::Mutate(
    absl::Span<const MutationInputRef> inputs, size_t num_mutants) {
  if (num_mutants == 0 || inputs.empty() || CheckFailure()) {
    return {};
  }

  std::vector<FuzzTestInputHandle> origin_inputs;
  std::vector<FuzzTestInputHandle> emitted_inputs;
  absl::Cleanup clean_up_inputs = [&] {
    for (FuzzTestInputHandle handle : origin_inputs) {
      adapter_.FreeInput(adapter_.ctx, handle);
    }
    origin_inputs.clear();
    for (FuzzTestInputHandle handle : emitted_inputs) {
      adapter_.FreeInput(adapter_.ctx, handle);
    }
    emitted_inputs.clear();
  };

  const auto input_sink = GetInputSinkTo(emitted_inputs);
  origin_inputs.reserve(inputs.size());

  for (const MutationInputRef& input : inputs) {
    const FuzzTestBytesView input_content{input.data.data(), input.data.size()};
    adapter_.DeserializeInputContent(adapter_.ctx, &input_content, &input_sink);
    if (CheckFailure()) {
      return {};
    }
    FUZZTEST_CHECK_EQ(emitted_inputs.size(), 1)
        << "DeserializeInputContent must emit exactly one input";
    if (adapter_.UpdateInputMetadata != nullptr && input.metadata != nullptr) {
      const FuzzTestBytesView input_metadata{input.metadata->cmp_data.data(),
                                             input.metadata->cmp_data.size()};
      adapter_.UpdateInputMetadata(adapter_.ctx, &input_metadata,
                                   emitted_inputs[0]);
      if (CheckFailure()) {
        return {};
      }
    }
    origin_inputs.push_back(emitted_inputs[0]);
    emitted_inputs.clear();
  }

  const int cross_over_level = env_.crossover_level <= 100
                                   ? static_cast<int>(env_.crossover_level)
                                   : kDefaultCrossOverLevel;
  std::vector<Mutant> mutants;
  mutants.reserve(num_mutants);
  ByteArray mutant_bytes;
  const auto mutant_bytes_sink = GetBytesSinkTo(mutant_bytes);

  for (size_t i = 0; i < num_mutants; ++i) {
    const size_t origin = rng_() % origin_inputs.size();
    const bool do_cross_over =
        adapter_.CrossOver != nullptr &&
        static_cast<int>(rng_() % 100) < cross_over_level;
    if (do_cross_over) {
      const size_t other = rng_() % origin_inputs.size();
      adapter_.CrossOver(adapter_.ctx, origin_inputs[origin],
                         origin_inputs[other], &input_sink);
    } else {
      adapter_.Mutate(adapter_.ctx, origin_inputs[origin], /*shrink=*/0,
                      &input_sink);
    }
    if (CheckFailure()) {
      return {};
    }
    FUZZTEST_CHECK_EQ(emitted_inputs.size(), 1)
        << (do_cross_over ? "CrossOver must emit exactly one input"
                          : "Mutate must emit exactly one input");
    mutant_bytes.clear();
    adapter_.SerializeInputContent(adapter_.ctx, emitted_inputs[0],
                                   &mutant_bytes_sink);
    adapter_.FreeInput(adapter_.ctx, emitted_inputs[0]);
    emitted_inputs.clear();
    if (CheckFailure()) {
      return {};
    }
    mutants.push_back(Mutant{mutant_bytes, origin});
  }

  if (CheckFailure()) {
    return {};
  }
  return mutants;
}

bool InProcessCentipedeCallbacks::Execute(std::string_view binary,
                                          absl::Span<const ByteSpan> inputs,
                                          BatchResult& batch_result) {
  batch_result.ClearAndResize(inputs.size());
  batch_result.failure_description().clear();
  batch_result.failure_signature().clear();

  if (CheckFailure()) {
    MoveFailureToBatchResult(batch_result);
    return false;
  }

  Timer timer;
  std::vector<uint64_t> features;
  std::vector<FuzzTestInputHandle> emitted_inputs;
  absl::Cleanup clean_up_emitted_inputs = [&] {
    for (FuzzTestInputHandle handle : emitted_inputs) {
      adapter_.FreeInput(adapter_.ctx, handle);
    }
    emitted_inputs.clear();
  };
  const auto input_sink = GetInputSinkTo(emitted_inputs);

  for (size_t i = 0; i < inputs.size(); ++i) {
    if (stop_condition_.ShouldStop()) {
      return true;
    }

    ExecutionResult::Stats stats = {};
    (void)timer.UsecSinceLast();

    const FuzzTestBytesView input_content{inputs[i].data(), inputs[i].size()};
    adapter_.DeserializeInputContent(adapter_.ctx, &input_content, &input_sink);
    if (CheckFailure()) {
      MoveFailureToBatchResult(batch_result);
      return false;
    }
    FUZZTEST_CHECK_EQ(emitted_inputs.size(), 1)
        << "DeserializeInputContent must emit exactly one input";
    const FuzzTestInputHandle input = emitted_inputs[0];

    features.clear();
    FuzzTestFeedbackSink feedback_sink = {
        /*ctx=*/reinterpret_cast<FuzzTestFeedbackSinkCtx*>(&features),
        /*EmitCoverageFeatures=*/
        [](FuzzTestFeedbackSinkCtx* ctx,
           const FuzzTestUint64sView* features_view) {
          auto* output = reinterpret_cast<std::vector<uint64_t>*>(ctx);
          output->insert(output->end(), features_view->data,
                         features_view->data + features_view->size);
        },
    };

    in_adapter_execute_.store(true, std::memory_order_relaxed);
    stats.prep_time_usec = timer.UsecSinceLast();
    adapter_.Execute(adapter_.ctx, input, &feedback_sink);
    stats.exec_time_usec = timer.UsecSinceLast();
    in_adapter_execute_.store(false, std::memory_order_relaxed);
    // Ensures that EmitFinding() observes `in_adapter_execute_ == false` if it
    // races with the CheckFailure() below and loses.
    SyncWithLaterFailureEmitters();
    if (CheckFailure()) {
      MoveFailureToBatchResult(batch_result);
      return false;
    }
    // At this point all failures emitted later must be errors.

    ExecutionResult& exec_result = batch_result.results()[i];
    if (adapter_.SerializeInputMetadata != nullptr) {
      const auto metadata_sink =
          GetBytesSinkTo(exec_result.metadata().cmp_data);
      adapter_.SerializeInputMetadata(adapter_.ctx, input, &metadata_sink);
    }
    adapter_.FreeInput(adapter_.ctx, input);
    emitted_inputs.clear();

    if (CheckFailure()) {
      exec_result.clear();
      MoveFailureToBatchResult(batch_result);
      return false;
    }

    FeatureVec& converted_features = exec_result.mutable_features();
    converted_features.resize(features.size());
    for (size_t j = 0; j < features.size(); ++j) {
      const uint64_t feature = features[j];
      const uint64_t domain_id =
          Bits(feature, kFuzzTestCoverageDomainIdStartBit,
               kFuzzTestCoverageDomainIdBitSize);
      FUZZTEST_CHECK(coverage_domains_[domain_id].registered)
          << "Emitted features in unregistered domain: " << domain_id;
      const auto& domain = coverage_domains_[domain_id];
      uint64_t feature_id = Bits(feature, kFuzzTestCoverageFeatureIdStartBit,
                                 domain.feature_id_bit_size);
      uint64_t counter = Bits(feature, kFuzzTestCoverageCounterStartBit,
                              domain.counter_bit_size);
      if (domain.counter_bit_size > 0) {
        counter =
            Bits(counter, std::max<size_t>(6, domain.counter_bit_size) - 6, 6);
        feature_id = (feature_id << 6) | counter;
      }
      converted_features[j] =
          feature_domains::Domain{domain_id}.ConvertToMe(feature_id);
    }

    stats.post_time_usec = timer.UsecSinceLast();
    stats.peak_rss_mb = GetPeakRSSMb();
    exec_result.stats() = stats;
    ++batch_result.num_outputs_read();
  }

  return true;
}

}  // namespace fuzztest::internal
