// Copyright 2026 The FuzzTest Authors.
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
#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <type_traits>
#include <vector>

#include "absl/base/nullability.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"
#include "./centipede/engine_abi.h"
#include "./centipede/engine_worker_abi.h"
#include "./centipede/execution_metadata.h"
#include "./centipede/feature.h"
#include "./centipede/runner_request.h"
#include "./centipede/runner_result.h"
#include "./centipede/runner_utils.h"
#include "./centipede/shared_memory_blob_sequence.h"
#include "./common/defs.h"

namespace fuzztest::internal {

namespace {

// Logging needs to be signal-safe and thread-safe.

struct LogErrNo {
  int saved_errno = errno;
};
struct LogLnSync {};

void WorkerLog() {}

template <typename T, typename... Rest>
void WorkerLog(const T& first, const Rest&... rest) {
  if constexpr (std::is_same_v<LogErrNo, T>) {
    char err_buf[80];
    const auto err_str = [&]() -> std::string_view {
      static constexpr std::string_view kFallbackMsg = "[strerror_r failed]";
      auto result = strerror_r(first.saved_errno, err_buf, sizeof(err_buf));
      constexpr bool xsi_strerror_r = std::is_same_v<decltype(result), int>;
      constexpr bool gnu_strerror_r = std::is_same_v<decltype(result), char*>;
      static_assert(xsi_strerror_r || gnu_strerror_r,
                    "unsupported strerror_r return type");
      if constexpr (xsi_strerror_r) {
        if (result != 0) return kFallbackMsg;
        return err_buf;
      } else if constexpr (gnu_strerror_r) {
        if (result == nullptr) return kFallbackMsg;
        return result;
      }
    }();
    WorkerLog(err_str);
  } else if constexpr (std::is_same_v<LogLnSync, T>) {
    write(STDERR_FILENO, "\n", 1);
    fsync(STDERR_FILENO);
  } else {
    std::string_view sv = first;
    while (!sv.empty()) {
      const int r = write(STDERR_FILENO, sv.data(), sv.size());
      if (r <= 0) break;
      sv = sv.substr(r);
    }
  }
  WorkerLog(rest...);
}

void WorkerEmitError(std::string_view message);

inline void WorkerCheck(bool condition, std::string_view error) {
  if (!condition) {
    WorkerEmitError(error);
    std::_Exit(1);
  }
}

struct WorkerFlags {
  bool present;
  // length of the flags string, excluding the ending '\0'.
  size_t len;
  const char* str;
};

// The first call of this function must be outside of signal handlers since it
// allocates memory (enforced by `GetWorkerFlagsEarly`). After that it would be
// signal-safe.
//
// The worker flags format is `:(NAME=VALUE|SWITCH:)+`. `GetWorkerFlags`
// replaces `:` with '\0' so that we can get null-terminated strings of VALUE
// without copying them, which is important for signal-safety.
const WorkerFlags& GetWorkerFlags() {
  static auto worker_flags = []() -> WorkerFlags {
    // TODO(xinhaoyuan): Rename the env name to FUZZTEST_WORKER_FLAGS.
    const char* env_flags = std::getenv("CENTIPEDE_RUNNER_FLAGS");
    if (env_flags == nullptr) {
      return {};
    }
    const size_t len = strlen(env_flags);
    char* str = reinterpret_cast<char*>(malloc(len + 1));
    if (str == nullptr) {
      WorkerLog("Cannot allocate the worker flags", LogLnSync{});
      std::_Exit(1);
    }
    memcpy(str, env_flags, len);
    str[len] = 0;
    WorkerLog("Got worker flags ", std::string_view{str, len}, LogLnSync{});
    // Post-processing to make '\0' as the separator, making each item as a
    // null-terminating string to be used without copying it.
    for (size_t i = 0; i < len; ++i) {
      if (str[i] == ':') str[i] = 0;
    }
    return WorkerFlags{true, len, str};
  }();
  return worker_flags;
}

__attribute__((constructor(200))) void GetWorkerFlagsEarly() {
  (void)GetWorkerFlags();
}

// `header` should be in the form of `FLAG_NAME=`.
//
// Extracts "value" as a null-terminated string from "\0FLAG_NAME=value\0" in
// the flags. Returns nullptr if it is not found.
const char* GetWorkerFlag(std::string_view header) {
  if (header.empty()) return nullptr;
  const auto& worker_flags = GetWorkerFlags();
  if (!worker_flags.present) return nullptr;
  const auto flags = std::string_view{worker_flags.str, worker_flags.len};
  size_t pos = 0;
  while (pos = flags.find(header, pos),
         pos != flags.npos && pos + header.size() < flags.size()) {
    if (pos > 0 && flags[pos - 1] == '\0') {
      return worker_flags.str + pos + header.size();
    }
    pos += header.size();
  }
  return nullptr;
}

// Checks whether "\0{name}\0" exists in the flags.
bool HasWorkerSwitchFlag(std::string_view name) {
  if (name.empty()) return false;
  const auto& worker_flags = GetWorkerFlags();
  if (!worker_flags.present) return false;
  const auto flags = std::string_view{worker_flags.str, worker_flags.len};
  size_t pos = 0;
  while (pos = flags.find(name, pos),
         pos != flags.npos && pos + name.size() < flags.size()) {
    if (pos > 0 && flags[pos - 1] == '\0' && flags[pos + name.size()] == '\0') {
      return true;
    }
    pos += name.size();
  }
  return false;
}

template <typename... C>
void TrySetFileContents(const char* absl_nonnull path, bool append,
                        C... contents) {
  // Needs to be signal-safe.
  int f = open(path, O_CREAT | O_WRONLY | (append ? O_APPEND : O_TRUNC),
               /*mode=*/0660);
  if (f == -1) {
    WorkerLog("cannot open path ", path, ": ", LogErrNo{}, LogLnSync{});
    return;
  }
  ([&] {
    std::string_view sv = contents;
    while (!sv.empty()) {
      const int r = write(f, sv.data(), sv.size());
      if (r < 0) {
        WorkerLog("write() failed on ", path, ": ", LogErrNo{}, LogLnSync{});
        return false;
      }
      if (r == 0) {
        WorkerLog("write() on ", path,
                  " returns 0 unexpectedly. Stopping writing the file.");
        return false;
      }
      sv = sv.substr(r);
    }
    return true;
  }() &&
   ...);  // NOLINT - stop fighting with auto-fomatting.
  if (fsync(f) != 0) {
    WorkerLog("fsync() failed on ", path, ": ", LogErrNo{}, LogLnSync{});
  }
  if (close(f) != 0) {
    WorkerLog("close() failed on ", path, ": ", LogErrNo{}, LogLnSync{});
  }
}

enum class WorkerAction {
  kGetBinaryId,
  kListTests,
  kTestGetSeeds,
  kTestMutate,
  kTestExecute,
};

constexpr std::string_view kWorkerBinaryIdOutputFlagHeader =
    "binary_id_output=";
constexpr std::string_view kWorkerTestNameFlagHeader = "test=";
constexpr std::string_view kWorkerTestListingOutputFlagHeader =
    "test_listing_output=";
constexpr std::string_view kWorkerTestGetSeedsOutputDirFlagHeader =
    "arg1=";  // TODO: Use better flag names when standardizing the protocol.
constexpr std::string_view kWorkerFailureDescriptionPathFlagHeader =
    "failure_description_path=";
constexpr std::string_view kWorkerFailureSignaturePathFlagHeader =
    "failure_signature_path=";
constexpr std::string_view kWorkerInputsBlobSequencePathFlagHeader =
    "arg1=";  // TODO: Use better flag names when standardizing the protocol.
constexpr std::string_view kWorkerOutputsBlobSequencePathFlagHeader =
    "arg2=";  // TODO: Use better flag names when standardizing the protocol.

struct WorkerState {
  std::atomic<bool> has_failure_output = false;
  std::atomic<bool> has_error = false;
  std::atomic<bool> in_adapter_execute = false;
  std::atomic<bool> has_finding = false;
  std::atomic<bool> saved_binary_id = false;
};

WorkerState& GetWorkerState() {
  static ExplicitLifetime<WorkerState> worker_state;
  [[maybe_unused]] static bool construct_once = [] {
    worker_state.Construct();
    return true;
  }();
  return *worker_state;
}

#define WORKER_STRINGIFY_EXPANDED(o) #o
#define WORKER_STRINGIFY(o) WORKER_STRINGIFY_EXPANDED(o)
#define WORKER_CHECK_FOR_ERROR()                                             \
  do {                                                                       \
    WorkerCheck(!GetWorkerState().has_error.load(std::memory_order_relaxed), \
                "Worker must not have error on " __FILE__                    \
                ":" WORKER_STRINGIFY(__LINE__));                             \
  } while (0)

bool WorkerEmitFailureOutput(std::string_view prefix,
                             std::string_view message) {
  bool ignored = GetWorkerState().has_failure_output.exchange(true);
  if (!ignored) {
    if (const char* failure_description_path =
            GetWorkerFlag(kWorkerFailureDescriptionPathFlagHeader);
        failure_description_path != nullptr) {
      TrySetFileContents(failure_description_path,
                         /*append=*/false, prefix, message);
    } else {
      ignored = true;
    }
  }
  if (ignored) {
    WorkerLog("Ignored emitting failure output: ", message, LogLnSync{});
  } else {
    WorkerLog("Emitted failure output: ", message, LogLnSync{});
  }
  return !ignored;
}

void WorkerEmitError(std::string_view message) {
  GetWorkerState().has_error = true;
  WorkerEmitFailureOutput("SETUP FAILURE: ", message);
}

void WorkerEmitFinding(std::string_view description,
                       std::string_view signature) {
  WorkerCheck(
      GetWorkerState().in_adapter_execute.load(std::memory_order_relaxed),
      "Must emit finding in adapter execute");
  const bool ignored = GetWorkerState().has_finding.exchange(true);
  if (!ignored) {
    WorkerCheck(WorkerEmitFailureOutput("INPUT FAILURE: ", description),
                "Failed to emit failure output for the finding");
    if (const char* finding_signature_path =
            GetWorkerFlag(kWorkerFailureSignaturePathFlagHeader);
        finding_signature_path != nullptr) {
      TrySetFileContents(finding_signature_path,
                         /*append=*/false, signature);
    }
  }

  if (ignored) {
    WorkerLog("Ignored emitting finding ", description, LogLnSync{});
  } else {
    WorkerLog("Emitted finding ", description, LogLnSync{});
  }
}

inline std::string_view ToStringView(
    const FuzzTestBytesView* absl_nonnull bytes_view) {
  return {reinterpret_cast<const char*>(bytes_view->data), bytes_view->size};
}

inline std::string_view ToStringView(const std::vector<uint8_t>& bytes) {
  return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

BlobSequence* GetInputsBlobSequence() {
  static auto result = []() -> BlobSequence* {
    if (!HasWorkerSwitchFlag("shmem")) {
      return nullptr;
    }
    const char* input_path =
        GetWorkerFlag(kWorkerInputsBlobSequencePathFlagHeader);
    WorkerCheck(input_path != nullptr, "inputs blob sequence is missing");
    return new SharedMemoryBlobSequence(input_path);
  }();
  return result;
}

BlobSequence* GetOutputsBlobSequence() {
  static auto result = []() -> BlobSequence* {
    if (!HasWorkerSwitchFlag("shmem")) {
      return nullptr;
    }
    const char* output_path =
        GetWorkerFlag(kWorkerOutputsBlobSequencePathFlagHeader);
    WorkerCheck(output_path != nullptr, "outputs blob sequence is missing");
    return new SharedMemoryBlobSequence(output_path);
  }();
  return result;
}

WorkerAction GetWorkerAction() {
  static WorkerAction worker_action = [] {
    if (HasWorkerSwitchFlag("dump_binary_id")) {
      return WorkerAction::kGetBinaryId;
    }
    if (HasWorkerSwitchFlag("list_tests")) {
      return WorkerAction::kListTests;
    }
    if (HasWorkerSwitchFlag("dump_seed_inputs")) {
      return WorkerAction::kTestGetSeeds;
    }
    auto* inputs_blobseq = GetInputsBlobSequence();
    WorkerCheck(inputs_blobseq != nullptr, "input blob sequence is not found");
    auto request_type_blob = inputs_blobseq->Read();
    if (IsMutationRequest(request_type_blob)) {
      inputs_blobseq->Reset();
      return WorkerAction::kTestMutate;
    }
    if (IsExecutionRequest(request_type_blob)) {
      inputs_blobseq->Reset();
      return WorkerAction::kTestExecute;
    }
    WorkerCheck(false, "unknown worker action from the flags");
    // should not reach here.
    std::abort();
  }();
  return worker_action;
}

FuzzTestBytesSink GetBytesSinkTo(std::vector<uint8_t>& bytes) {
  return {
      /*ctx=*/reinterpret_cast<FuzzTestBytesSinkCtx*>(&bytes),
      /*Emit=*/[](FuzzTestBytesSinkCtx* ctx, const FuzzTestBytesView* view) {
        auto* output = reinterpret_cast<decltype(&bytes)>(ctx);
        output->insert(output->end(), view->data, view->data + view->size);
      }};
}

FuzzTestInputSink GetInputSinkTo(std::vector<FuzzTestInputHandle>& inputs) {
  return {/*ctx=*/reinterpret_cast<FuzzTestInputSinkCtx*>(&inputs),
          /*Emit=*/[](FuzzTestInputSinkCtx* ctx, FuzzTestInputHandle input) {
            auto* output = reinterpret_cast<decltype(&inputs)>(ctx);
            output->push_back(input);
          }};
}

void WorkerDoGetBinaryId(const FuzzTestAdapterManager& manager) {
  if (GetWorkerState().saved_binary_id.exchange(true)) return;
  const char* binary_id_output_path =
      GetWorkerFlag(kWorkerBinaryIdOutputFlagHeader);
  WorkerCheck(binary_id_output_path != nullptr,
              "binary ID output path is not set");
  std::vector<uint8_t> binary_id;
  const auto sink = GetBytesSinkTo(binary_id);
  manager.GetBinaryId(manager.ctx, &sink);
  WORKER_CHECK_FOR_ERROR();
  TrySetFileContents(binary_id_output_path,
                     /*append=*/false, ToStringView(binary_id));
}

void WorkerDoListCurrentTest(std::string_view test_name) {
  const char* test_listing_output_path =
      GetWorkerFlag(kWorkerTestListingOutputFlagHeader);
  WorkerCheck(test_listing_output_path != nullptr,
              "binary ID output path is not set");
  TrySetFileContents(test_listing_output_path,
                     /*append=*/true, test_name, "\n");
}

void WorkerDoGetSeeds(const FuzzTestAdapter& adapter) {
  std::vector<FuzzTestInputHandle> seed_handles;
  const auto sink = GetInputSinkTo(seed_handles);
  if (adapter.GetPresetSeedInputs != nullptr) {
    adapter.GetPresetSeedInputs(adapter.ctx, &sink);
    WORKER_CHECK_FOR_ERROR();
  }

  // TODO(xinhaoyuan): Make 32 adjustable.
  while (seed_handles.size() < 32) {
    const size_t prev_size = seed_handles.size();
    adapter.GetRandomSeedInput(adapter.ctx, &sink);
    WorkerCheck(seed_handles.size() == prev_size + 1,
                "GetRandomSeedInput must emit exactly one input");
  }

  static const char* output_dir =
      GetWorkerFlag(kWorkerTestGetSeedsOutputDirFlagHeader);
  WorkerCheck(output_dir != nullptr, "seeds output path must be specified");

  for (size_t i = 0; i < seed_handles.size(); ++i) {
    char seed_path_buf[PATH_MAX];
    const size_t num_path_chars =
        snprintf(seed_path_buf, PATH_MAX, "%s/%09lu", output_dir, i);
    WorkerCheck(num_path_chars < PATH_MAX, "seed path reaches PATH_MAX");
    std::vector<uint8_t> serialized_input;
    const auto sink = GetBytesSinkTo(serialized_input);
    adapter.SerializeInputContent(adapter.ctx, seed_handles[i], &sink);
    FILE* output_file = fopen(seed_path_buf, "w");
    WorkerCheck(output_file != nullptr, "failed to open the seed file");
    const size_t num_bytes_written = fwrite(
        serialized_input.data(), 1, serialized_input.size(), output_file);
    WorkerCheck(num_bytes_written == serialized_input.size(),
                "wrong number of bytes written for seed");
    fclose(output_file);
    adapter.FreeInput(adapter.ctx, seed_handles[i]);
  }
}

absl::BitGenRef GetBitGen() {
  static thread_local std::unique_ptr<absl::BitGen> bitgen;
  if (bitgen == nullptr) {
    bitgen = std::make_unique<absl::BitGen>();
  }
  return *bitgen;
}

void WorkerDoMutate(const FuzzTestAdapter& adapter) {
  auto* inputs_blobseq = GetInputsBlobSequence();
  auto* outputs_blobseq = GetOutputsBlobSequence();
  WorkerCheck(inputs_blobseq != nullptr && outputs_blobseq != nullptr,
              "inputs/outputs blob sequences must be specified");

  WorkerCheck(MutationResult::WriteHasCustomMutator(true, *outputs_blobseq),
              "Failed to write custom mutator indicator!");

  // Read max_num_mutants.
  size_t num_mutants = 0;
  size_t num_inputs = 0;
  WorkerCheck(IsMutationRequest(inputs_blobseq->Read()),
              "Not mutation request!");
  WorkerCheck(IsNumMutants(inputs_blobseq->Read(), num_mutants),
              "No num mutants");
  WorkerCheck(IsNumInputs(inputs_blobseq->Read(), num_inputs), "No num inputs");

  std::vector<FuzzTestInputHandle> origin_inputs;
  std::vector<FuzzTestInputHandle> emitted_inputs;
  const auto input_sink = GetInputSinkTo(emitted_inputs);
  origin_inputs.reserve(num_inputs);
  for (size_t i = 0; i < num_inputs; ++i) {
    // If inputs_blobseq have overflown in the engine, we still want to
    // handle the first few inputs.
    ExecutionMetadata metadata;
    if (!IsExecutionMetadata(inputs_blobseq->Read(), metadata)) {
      break;
    }
    auto blob = inputs_blobseq->Read();
    if (!IsDataInput(blob)) break;
    emitted_inputs.clear();
    auto input_content = FuzzTestBytesView{blob.data, blob.size};
    auto input_metadata =
        FuzzTestBytesView{metadata.cmp_data.data(), metadata.cmp_data.size()};
    adapter.DeserializeInputContent(adapter.ctx, &input_content, &input_sink);
    WORKER_CHECK_FOR_ERROR();
    WorkerCheck(emitted_inputs.size() == 1,
                "DeserializeInputContent must emit exactly one input");
    if (adapter.UpdateInputMetadata != nullptr) {
      adapter.UpdateInputMetadata(adapter.ctx, &input_metadata,
                                  emitted_inputs[0]);
    }
    WORKER_CHECK_FOR_ERROR();
    origin_inputs.push_back(emitted_inputs[0]);
  }

  if (origin_inputs.empty()) return;

  std::vector<uint8_t> mutant_bytes;
  const auto mutant_bytes_sink = GetBytesSinkTo(mutant_bytes);
  for (size_t i = 0; i < num_mutants; ++i) {
    const auto origin =
        absl::Uniform<size_t>(GetBitGen(), 0, origin_inputs.size());
    emitted_inputs.clear();
    adapter.Mutate(adapter.ctx, origin_inputs[origin], /*shrink=*/0,
                   &input_sink);
    WORKER_CHECK_FOR_ERROR();
    WorkerCheck(emitted_inputs.size() == 1,
                "Mutate must emit exactly one input");
    mutant_bytes.clear();
    adapter.SerializeInputContent(adapter.ctx, emitted_inputs[0],
                                  &mutant_bytes_sink);
    WORKER_CHECK_FOR_ERROR();
    WorkerCheck(MutationResult::WriteMutant(MutantRef{mutant_bytes, origin},
                                            *outputs_blobseq),
                "failed to write mutant");
    adapter.FreeInput(adapter.ctx, emitted_inputs[0]);
    WORKER_CHECK_FOR_ERROR();
  }

  for (auto input : origin_inputs) {
    adapter.FreeInput(adapter.ctx, input);
    WORKER_CHECK_FOR_ERROR();
  }
}

template <typename T>
constexpr T Bits(T v, size_t begin, size_t size) {
  return (v >> begin) & ((T{1} << size) - 1);
}

struct CoverageDomainConfiguration {
  bool registered = false;
  std::string name;
  uint8_t feature_id_bit_size;
  uint8_t counter_bit_size;
};
std::array<CoverageDomainConfiguration, 1 << kFuzzTestCoverageDomainIdBitSize>
    coverage_domains;

void WorkerDoExecute(const FuzzTestAdapter& adapter) {
  auto* inputs_blobseq = GetInputsBlobSequence();
  auto* outputs_blobseq = GetOutputsBlobSequence();
  WorkerCheck(inputs_blobseq != nullptr && outputs_blobseq != nullptr,
              "inputs/ouptuts blob sequence must exist");

  size_t num_inputs = 0;
  WorkerCheck(IsExecutionRequest(inputs_blobseq->Read()),
              "not an execution request");
  WorkerCheck(IsNumInputs(inputs_blobseq->Read(), num_inputs),
              "failed to read num_inputs");

  [[maybe_unused]] static bool get_coverage_domain = [&] {
    FuzzTestCoverageDomainRegistry registry = {
        /*ctx=*/nullptr,
        /*Register=*/[](FuzzTestCoverageDomainRegistryCtx* ctx,
                        const FuzzTestCoverageDomain* domain) {
          WorkerCheck(
              domain->domain_id < (1 << kFuzzTestCoverageDomainIdBitSize),
              "domain ID is too large");
          WorkerCheck(
              domain->feature_id_bit_size <= kFuzzTestCoverageFeatureIdBitSize,
              "domain feature id bit size is too large");
          WorkerCheck(
              domain->counter_bit_size <= kFuzzTestCoverageCounterBitSize,
              "domain counter bit size is too large");
          WorkerCheck(!coverage_domains[domain->domain_id].registered,
                      "domain ID is already registered");
          coverage_domains[domain->domain_id].registered = true;
          coverage_domains[domain->domain_id].name =
              ToStringView(&domain->name);
          coverage_domains[domain->domain_id].feature_id_bit_size =
              domain->feature_id_bit_size;
          coverage_domains[domain->domain_id].counter_bit_size =
              domain->counter_bit_size;
        }};
    adapter.SetUpCoverageDomains(adapter.ctx, &registry);
    return true;
  }();

  // In-loop variables declared outside to save allocations.
  std::vector<uint64_t> features;
  std::vector<uint8_t> serialized_metadata;
  std::vector<FuzzTestInputHandle> emitted_inputs;
  const auto input_sink = GetInputSinkTo(emitted_inputs);

  for (size_t i = 0; i < num_inputs; i++) {
    auto blob = inputs_blobseq->Read();
    if (!blob.IsValid()) return;  // no more blobs to read.
    WorkerCheck(IsDataInput(blob), "Must read data input");

    if (!BatchResult::WriteInputBegin(*outputs_blobseq)) {
      WorkerLog("failed to write input begin");
      break;
    }

    emitted_inputs.clear();
    const auto input_content = FuzzTestBytesView{blob.data, blob.size};
    adapter.DeserializeInputContent(adapter.ctx, &input_content, &input_sink);
    WORKER_CHECK_FOR_ERROR();
    WorkerCheck(emitted_inputs.size() == 1,
                "Deserialize must emit exactly one input");
    auto input = emitted_inputs[0];

    features.clear();
    FuzzTestFeedbackSink feedback_sink = {
        /*ctx=*/reinterpret_cast<FuzzTestFeedbackSinkCtx*>(&features),
        /*EmitFeatures=*/[](FuzzTestFeedbackSinkCtx* ctx,
                            const FuzzTestUint64sView* features) {
          auto* output = reinterpret_cast<std::vector<uint64_t>*>(ctx);
          output->insert(output->end(), features->data,
                         features->data + features->size);
        }};

    GetWorkerState().in_adapter_execute = true;
    adapter.Execute(adapter.ctx, input, &feedback_sink);
    GetWorkerState().in_adapter_execute = false;
    WORKER_CHECK_FOR_ERROR();

    serialized_metadata.clear();
    if (adapter.SerializeInputMetadata != nullptr) {
      const auto metadata_sink = GetBytesSinkTo(serialized_metadata);
      adapter.SerializeInputMetadata(adapter.ctx, input, &metadata_sink);
    }
    adapter.FreeInput(adapter.ctx, input);
    WORKER_CHECK_FOR_ERROR();

    if (GetWorkerState().has_finding.load(std::memory_order_relaxed)) return;

    // Convert to the Centipede feature layout with possible loss.
    for (auto& feature : features) {
      const uint64_t domain_id =
          Bits(feature, kFuzzTestCoverageDomainIdStartBit,
               kFuzzTestCoverageDomainIdBitSize);
      WorkerCheck(coverage_domains[domain_id].registered,
                  "Emitted features in unregistered domain");
      const auto& domain = coverage_domains[domain_id];
      uint64_t feature_id = Bits(feature, kFuzzTestCoverageFeatureIdStartBit,
                                 domain.feature_id_bit_size);
      uint64_t counter = Bits(feature, kFuzzTestCoverageCounterStartBit,
                              domain.counter_bit_size);
      if (coverage_domains[domain_id].counter_bit_size > 0) {
        // Assume that `domain_id` is one of the scoring domains in Centipede,
        // which uses the lower 6 bits for the counter value. The conversion is
        // done by shifting the 6 highest bits of `counter` into the lower bits
        // of `feature_id`. The higher bits of `feature_id` can possibly be
        // truncated. These should not be concerns for sancov features. For
        // other feedback sources, the loss can cause lower effectiveness but it
        // should not break the fuzzing.
        counter =
            Bits(counter, std::max<size_t>(6, domain.counter_bit_size) - 6, 6);
        feature_id = (feature_id << 6) | counter;
      }
      feature = feature_domains::Domain{domain_id}.ConvertToMe(feature_id);
    }

    if (!BatchResult::WriteOneFeatureVec(features.data(), features.size(),
                                         *outputs_blobseq)) {
      WorkerLog("failed to write feedback");
      break;
    }
    if (!BatchResult::WriteMetadata(serialized_metadata, *outputs_blobseq)) {
      WorkerLog("failed to write input metadata");
      break;
    }
    if (!BatchResult::WriteInputEnd(*outputs_blobseq)) {
      WorkerLog("failed to write input end");
      break;
    }
  }
}

const char* FuzzTestWorkerGetTestName() {
  static auto test_name = []() -> const char* {
    return GetWorkerFlag(kWorkerTestNameFlagHeader);
  }();
  return test_name;
}

FuzzTestWorkerStatus WorkerMaybeRun(const FuzzTestAdapterManager& manager) {
  const auto& flags = GetWorkerFlags();
  if (!flags.present) return kFuzzTestWorkerNotRequired;

  if (HasWorkerSwitchFlag("dump_configuration")) {
    return kFuzzTestWorkerSuccess;
  }

  const auto action = GetWorkerAction();
  if (action == WorkerAction::kGetBinaryId) {
    WorkerDoGetBinaryId(manager);
    return kFuzzTestWorkerSuccess;
  }

  WorkerCheck(manager.GetTestName != nullptr, "GetTestName is not defined");

  std::vector<uint8_t> test_name;
  const auto sink = GetBytesSinkTo(test_name);
  manager.GetTestName(manager.ctx, &sink);
  WORKER_CHECK_FOR_ERROR();

  if (action == WorkerAction::kListTests) {
    WorkerDoListCurrentTest(ToStringView(test_name));
    return kFuzzTestWorkerSuccess;
  }

  const char* worker_test_name = FuzzTestWorkerGetTestName();
  WorkerCheck(worker_test_name != nullptr,
              "Worker requested test name must not be empty");
  if (ToStringView(test_name) != worker_test_name) {
    return kFuzzTestWorkerSuccess;
  }

  static const FuzzTestDiagnosticSink diagnostic_sink = {
      /*ctx=*/nullptr,
      /*EmitError=*/
      [](FuzzTestDiagnosticSinkCtx* ctx, const FuzzTestBytesView* message) {
        WorkerEmitError(ToStringView(message));
      },
      /*EmitWarning=*/
      [](FuzzTestDiagnosticSinkCtx* ctx, const FuzzTestBytesView* message) {
        // TODO(xinhaoyuan): Emit the warning to the engine.
        WorkerLog("Got warning ", ToStringView(message));
      },
      /*EmitFinding=*/
      [](FuzzTestDiagnosticSinkCtx* ctx, const FuzzTestBytesView* description,
         const FuzzTestBytesView* signature) {
        WorkerEmitFinding(ToStringView(description), ToStringView(signature));
      },
  };
  WorkerCheck(manager.ConstructAdapter != nullptr,
              "ConstructAdapter is not defined");
  FuzzTestAdapter adapter = {};
  manager.ConstructAdapter(manager.ctx, /*diagnostic_sink=*/&diagnostic_sink,
                           &adapter);
  WORKER_CHECK_FOR_ERROR();
  WorkerCheck(adapter.SetUpCoverageDomains != nullptr,
              "SetUpCoverageDomains must be defined");
  WorkerCheck(adapter.GetRandomSeedInput != nullptr,
              "GetRandomSeedInput must be defined");
  WorkerCheck(adapter.Execute != nullptr, "Execute must be defined");
  WorkerCheck(adapter.Mutate != nullptr, "Mutate must be defined");
  WorkerCheck(adapter.SerializeInputContent != nullptr,
              "SerializeInputContent must be defined");
  WorkerCheck(adapter.DeserializeInputContent != nullptr,
              "DeserializeInputContent must be defined");
  WorkerCheck(adapter.FreeInput != nullptr, "FreeInput must be defined");
  WorkerCheck(adapter.FreeCtx != nullptr, "FreeCtx must be defined");

  if (action == WorkerAction::kTestGetSeeds) {
    WorkerDoGetSeeds(adapter);
  } else if (action == WorkerAction::kTestMutate) {
    WorkerDoMutate(adapter);
  } else if (action == WorkerAction::kTestExecute) {
    WorkerDoExecute(adapter);
  } else {
    WorkerCheck(false, "unknown worker action to take");
  }

  adapter.FreeCtx(adapter.ctx);  // NOLINT
  WORKER_CHECK_FOR_ERROR();

  return GetWorkerState().has_finding.load(std::memory_order_relaxed)
             ? kFuzzTestWorkerFailure
             : kFuzzTestWorkerSuccess;
}

}  // namespace

}  // namespace fuzztest::internal

using ::fuzztest::internal::WorkerCheck;
using ::fuzztest::internal::WorkerMaybeRun;

FuzzTestWorkerStatus FuzzTestWorkerMaybeRun(
    const FuzzTestAdapterManager* manager) {
  WorkerCheck(manager != nullptr, "manager must not be nullptr");
  return WorkerMaybeRun(*manager);
}
