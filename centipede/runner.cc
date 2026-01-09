// Copyright 2022 The Centipede Authors.
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

// Fuzz target runner (engine) for Centipede.
// Reads the input files and feeds their contents to
// the fuzz target (RunnerCallbacks::Execute), then dumps the coverage data.
// If the input path is "/path/to/foo",
// the coverage features are dumped to "/path/to/foo-features"
//
// WARNING: please avoid any C++ libraries here, such as Absl and (most of) STL,
// in order to avoid creating new coverage edges in the binary.
#include "./centipede/runner.h"

#include <fcntl.h>
#include <pthread.h>  // NOLINT: use pthread to avoid extra dependencies.
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/base/nullability.h"
#include "absl/base/optimization.h"
#include "./centipede/byte_array_mutator.h"
#include "./centipede/dispatcher_flag_helper.h"
#include "./centipede/execution_metadata.h"
#include "./centipede/feature.h"
#include "./centipede/mutation_input.h"
#include "./centipede/runner_interface.h"
#include "./centipede/runner_request.h"
#include "./centipede/runner_result.h"
#include "./centipede/runner_utils.h"
#include "./centipede/sancov_runtime.h"
#include "./centipede/sancov_state.h"
#include "./centipede/shared_memory_blob_sequence.h"
#include "./common/defs.h"

namespace fuzztest::internal {

ExplicitLifetime<GlobalRunnerState> state;

namespace {

struct GlobalRunnerStateManager {
  GlobalRunnerStateManager() { state.Construct(); }

  ~GlobalRunnerStateManager() { state->OnTermination(); }
};

GlobalRunnerStateManager state_manager __attribute__((init_priority(200)));

}  // namespace

static size_t GetPeakRSSMb() {
  struct rusage usage = {};
  if (getrusage(RUSAGE_SELF, &usage) != 0) return 0;
#ifdef __APPLE__
  // On MacOS, the unit seems to be byte according to experiment, while some
  // documents mentioned KiB. This could depend on OS variants.
  return usage.ru_maxrss >> 20;
#else   // __APPLE__
  // On Linux, ru_maxrss is in KiB
  return usage.ru_maxrss >> 10;
#endif  // __APPLE__
}

// Returns the current time in microseconds.
static uint64_t TimeInUsec() {
  struct timeval tv = {};
  constexpr size_t kUsecInSec = 1000000;
  gettimeofday(&tv, nullptr);
  return tv.tv_sec * kUsecInSec + tv.tv_usec;
}

// Atomic flags to make sure that (a) watchdog failure is reported only for
// the current input, and (b) only one thread is handling watchdog failures.

// True if the watchdog thread is detecting failures, false otherwise.
static std::atomic<bool> watchdog_thread_busy = false;
// True if a watchdog failure is found, false otherwise.
static std::atomic<bool> watchdog_failure_found = false;

static void WaitWatchdogThreadIdle() {
  while (ABSL_PREDICT_FALSE(watchdog_thread_busy.load())) {
    if (ABSL_PREDICT_FALSE(watchdog_failure_found.load())) {
      // A failure is found - wait for the process to terminate.
      sleep(1);  // NOLINT
    } else {
      // Busy-wait for the detection.
      sleep(0);  // NOLINT
    }
  }
}

static void CheckWatchdogLimits() {
  const uint64_t curr_time = time(nullptr);
  struct Resource {
    const char *what;
    const char *units;
    uint64_t value;
    uint64_t limit;
    bool ignore_report;
    const char *failure;
  };
  const uint64_t input_start_time = state->input_start_time;
  const uint64_t batch_start_time = state->batch_start_time;
  if (input_start_time == 0 || batch_start_time == 0) return;
  const Resource resources[] = {
      {Resource{
          /*what=*/"Per-input timeout",
          /*units=*/"sec",
          /*value=*/curr_time - input_start_time,
          /*limit=*/state->run_time_flags.timeout_per_input,
          /*ignore_report=*/
          state->run_time_flags.ignore_timeout_reports != 0,
          /*failure=*/kExecutionFailurePerInputTimeout.data(),
      }},
      {Resource{
          /*what=*/"Per-batch timeout",
          /*units=*/"sec",
          /*value=*/curr_time - batch_start_time,
          /*limit=*/state->run_time_flags.timeout_per_batch,
          /*ignore_report=*/
          state->run_time_flags.ignore_timeout_reports != 0,
          /*failure=*/kExecutionFailurePerBatchTimeout.data(),
      }},
      {Resource{
          /*what=*/"RSS limit",
          /*units=*/"MB",
          /*value=*/GetPeakRSSMb(),
          /*limit=*/state->run_time_flags.rss_limit_mb,
          /*ignore_report=*/false,
          /*failure=*/kExecutionFailureRssLimitExceeded.data(),
      }},
  };
  for (const auto &resource : resources) {
    if (resource.limit != 0 && resource.value > resource.limit) {
      if (!watchdog_failure_found.exchange(true)) {
        if (resource.ignore_report) {
          fprintf(stderr,
                  "========= %s exceeded: %" PRIu64 " > %" PRIu64
                  " (%s); exiting without reporting as an error\n",
                  resource.what, resource.value, resource.limit,
                  resource.units);
          std::_Exit(0);
          // should not return here.
        }
        fprintf(stderr,
                "========= %s exceeded: %" PRIu64 " > %" PRIu64
                " (%s); exiting\n",
                resource.what, resource.value, resource.limit, resource.units);
        fprintf(
            stderr,
            "=============================================================="
            "===\n"
            "=== BUG FOUND!\n The %s is set to %" PRIu64
            " (%s), but it exceeded %" PRIu64
            ".\n"
            "Find out how to adjust the resource limits at "
            "https://github.com/google/fuzztest/tree/main/doc/flags-reference.md"
            "\n",
            resource.what, resource.limit, resource.units, resource.value);
        CentipedeSetFailureDescription(resource.failure);
        std::abort();
      }
    }
  }
}

// Watchdog thread. Periodically checks if it's time to abort due to a
// timeout/OOM.
[[noreturn]] static void *WatchdogThread(void *unused) {
  // Since the watchdog is internal and does not execute user code, disable
  // SanCov tracing and TLS traversal.
  tls.traced = false;
  tls.ignore = true;
  state->watchdog_thread_started = true;
  while (true) {
    sleep(1);

    // No calls to ResetInputTimer() yet: input execution hasn't started.
    if (state->input_start_time == 0) continue;

    watchdog_thread_busy = true;
    CheckWatchdogLimits();
    watchdog_thread_busy = false;
  }
}

__attribute__((noinline)) void CheckStackLimit(uintptr_t sp) {
  static std::atomic_flag stack_limit_exceeded = ATOMIC_FLAG_INIT;
  const size_t stack_limit = state->run_time_flags.stack_limit_kb.load() << 10;
  // Check for the stack limit only if sp is inside the stack region.
  if (stack_limit > 0 && tls.stack_region_low &&
      tls.top_frame_sp - sp > stack_limit) {
    const bool test_not_running = state->input_start_time == 0;
    if (test_not_running) return;
    if (stack_limit_exceeded.test_and_set()) return;
    fprintf(stderr,
            "========= Stack limit exceeded: %" PRIuPTR
            " > %zu"
            " (byte); aborting\n",
            tls.top_frame_sp - sp, stack_limit);
    CentipedeSetFailureDescription(
        fuzztest::internal::kExecutionFailureStackLimitExceeded.data());
    std::abort();
  }
}

void GlobalRunnerState::StartWatchdogThread() {
  fprintf(stderr,
          "Starting watchdog thread: timeout_per_input: %" PRIu64
          " sec; timeout_per_batch: %" PRIu64 " sec; rss_limit_mb: %" PRIu64
          " MB; stack_limit_kb: %" PRIu64 " KB\n",
          run_time_flags.timeout_per_input.load(),
          run_time_flags.timeout_per_batch, run_time_flags.rss_limit_mb.load(),
          state->run_time_flags.stack_limit_kb.load());
  pthread_t watchdog_thread;
  pthread_create(&watchdog_thread, nullptr, WatchdogThread, nullptr);
  pthread_detach(watchdog_thread);
  // Wait until the watchdog actually starts and initializes itself.
  while (!state->watchdog_thread_started) {
    sleep(0);
  }
}

void GlobalRunnerState::ResetTimers() {
  const auto curr_time = time(nullptr);
  state->input_start_time = curr_time;
  // batch_start_time is set only once -- just before the first input of the
  // batch is about to start running.
  if (batch_start_time == 0) {
    batch_start_time = curr_time;
  }
}

// Byte array mutation fallback for a custom mutator, as defined here:
// https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md
extern "C" __attribute__((weak)) size_t
CentipedeLLVMFuzzerMutateCallback(uint8_t *data, size_t size, size_t max_size) {
  // TODO(kcc): [as-needed] fix the interface mismatch.
  // LLVMFuzzerMutate is an array-based interface (for compatibility reasons)
  // while ByteArray has a vector-based interface.
  // This incompatibility causes us to do extra allocate/copy per mutation.
  // It may not cause big problems in practice though.
  if (max_size == 0) return 0;  // just in case, not expected to happen.
  if (size == 0) {
    // Don't mutate empty data, just return a 1-byte result.
    data[0] = 0;
    return 1;
  }

  ByteArray array(data, data + size);
  state->byte_array_mutator->set_max_len(max_size);
  state->byte_array_mutator->Mutate(array);
  if (array.size() > max_size) {
    array.resize(max_size);
  }
  memcpy(data, array.data(), array.size());
  return array.size();
}

extern "C" size_t LLVMFuzzerMutate(uint8_t *data, size_t size,
                                   size_t max_size) {
  return CentipedeLLVMFuzzerMutateCallback(data, size, max_size);
}

// An arbitrary large size for input data.
static const size_t kMaxDataSize = 1 << 20;

static void WriteFeaturesToFile(FILE *file, const feature_t *features,
                                size_t size) {
  if (!size) return;
  auto bytes_written = fwrite(features, 1, sizeof(features[0]) * size, file);
  PrintErrorAndExitIf(bytes_written != size * sizeof(features[0]),
                      "wrong number of bytes written for coverage");
}

// Clears all coverage data.
// We still need to clear all the thread-local data updated during execution.
// If `full_clear==true` clear all coverage anyway - useful to remove the
// coverage accumulated during startup.
__attribute__((noinline))  // so that we see it in profile.
static void PrepareCoverage(bool full_clear) {
  CleanUpSancovTls();
  {
    fuzztest::internal::LockGuard lock(state->execution_result_override_mu);
    if (state->execution_result_override != nullptr) {
      state->execution_result_override->ClearAndResize(0);
    }
  }
  PrepareSancov(full_clear);
}

void RunnerCallbacks::GetSeeds(std::function<void(ByteSpan)> seed_callback) {
  seed_callback({0});
}

std::string RunnerCallbacks::GetSerializedTargetConfig() { return ""; }

bool RunnerCallbacks::Mutate(
    const std::vector<MutationInputRef> & /*inputs*/, size_t /*num_mutants*/,
    std::function<void(ByteSpan)> /*new_mutant_callback*/) {
  RunnerCheck(!HasCustomMutator(),
              "Class deriving from RunnerCallbacks must implement Mutate() if "
              "HasCustomMutator() returns true.");
  return true;
}

class LegacyRunnerCallbacks : public RunnerCallbacks {
 public:
  LegacyRunnerCallbacks(FuzzerTestOneInputCallback test_one_input_cb,
                        FuzzerCustomMutatorCallback custom_mutator_cb,
                        FuzzerCustomCrossOverCallback custom_crossover_cb)
      : test_one_input_cb_(test_one_input_cb),
        custom_mutator_cb_(custom_mutator_cb),
        custom_crossover_cb_(custom_crossover_cb) {}

  bool Execute(ByteSpan input) override {
    PrintErrorAndExitIf(test_one_input_cb_ == nullptr,
                        "missing test_on_input_cb");
    const int retval = test_one_input_cb_(input.data(), input.size());
    PrintErrorAndExitIf(
        retval != -1 && retval != 0,
        "test_on_input_cb returns invalid value other than -1 and 0");
    return retval == 0;
  }

  bool HasCustomMutator() const override {
    return custom_mutator_cb_ != nullptr;
  }

  bool Mutate(const std::vector<MutationInputRef> &inputs, size_t num_mutants,
              std::function<void(ByteSpan)> new_mutant_callback) override;

 private:
  FuzzerTestOneInputCallback test_one_input_cb_;
  FuzzerCustomMutatorCallback custom_mutator_cb_;
  FuzzerCustomCrossOverCallback custom_crossover_cb_;
};

std::unique_ptr<RunnerCallbacks> CreateLegacyRunnerCallbacks(
    FuzzerTestOneInputCallback test_one_input_cb,
    FuzzerCustomMutatorCallback custom_mutator_cb,
    FuzzerCustomCrossOverCallback custom_crossover_cb) {
  return std::make_unique<LegacyRunnerCallbacks>(
      test_one_input_cb, custom_mutator_cb, custom_crossover_cb);
}

static void RunOneInput(const uint8_t *data, size_t size,
                        RunnerCallbacks &callbacks) {
  state->stats = {};
  size_t last_time_usec = 0;
  auto UsecSinceLast = [&last_time_usec]() {
    uint64_t t = TimeInUsec();
    uint64_t ret_val = t - last_time_usec;
    last_time_usec = t;
    return ret_val;
  };
  UsecSinceLast();
  PrepareCoverage(/*full_clear=*/false);
  state->stats.prep_time_usec = UsecSinceLast();
  state->ResetTimers();
  int target_return_value = callbacks.Execute({data, size}) ? 0 : -1;
  state->stats.exec_time_usec = UsecSinceLast();
  CheckWatchdogLimits();
  if (fuzztest::internal::state->input_start_time.exchange(0) != 0) {
    PostProcessSancov(target_return_value == -1);
  }
  WaitWatchdogThreadIdle();
  state->stats.post_time_usec = UsecSinceLast();
  state->stats.peak_rss_mb = GetPeakRSSMb();
}

// Runs one input provided in file `input_path`.
// Produces coverage data in file `input_path`-features.
__attribute__((noinline))  // so that we see it in profile.
static void ReadOneInputExecuteItAndDumpCoverage(const char *input_path,
                                                 RunnerCallbacks &callbacks) {
  // Read the input.
  auto data = ReadBytesFromFilePath<uint8_t>(input_path);

  RunOneInput(data.data(), data.size(), callbacks);

  // Dump features to a file.
  char features_file_path[PATH_MAX];
  snprintf(features_file_path, sizeof(features_file_path), "%s-features",
           input_path);
  FILE *features_file = fopen(features_file_path, "w");
  PrintErrorAndExitIf(features_file == nullptr, "can't open coverage file");

  const SanCovRuntimeRawFeatureParts sancov_features =
      SanCovRuntimeGetFeatures();
  WriteFeaturesToFile(features_file, sancov_features.features,
                      sancov_features.num_features);
  fclose(features_file);
}

// Starts sending the outputs (coverage, etc.) to `outputs_blobseq`.
// Returns true on success.
static bool StartSendingOutputsToEngine(BlobSequence &outputs_blobseq) {
  return BatchResult::WriteInputBegin(outputs_blobseq);
}

// Copy all the sancov features to `data` with given `capacity` in bytes.
// Returns the byte size of sancov features.
static size_t CopyFeatures(uint8_t *data, size_t capacity) {
  const SanCovRuntimeRawFeatureParts sancov_features =
      SanCovRuntimeGetFeatures();
  const size_t features_len_in_bytes =
      sancov_features.num_features * sizeof(feature_t);
  if (features_len_in_bytes > capacity) return 0;
  memcpy(data, sancov_features.features, features_len_in_bytes);
  return features_len_in_bytes;
}

// Finishes sending the outputs (coverage, etc.) to `outputs_blobseq`.
// Returns true on success.
static bool FinishSendingOutputsToEngine(BlobSequence &outputs_blobseq) {
  {
    LockGuard lock(state->execution_result_override_mu);
    bool has_overridden_execution_result = false;
    if (state->execution_result_override != nullptr) {
      RunnerCheck(state->execution_result_override->results().size() <= 1,
                  "unexpected number of overridden execution results");
      has_overridden_execution_result =
          state->execution_result_override->results().size() == 1;
    }
    if (has_overridden_execution_result) {
      const auto& result = state->execution_result_override->results()[0];
      return BatchResult::WriteOneFeatureVec(result.features().data(),
                                             result.features().size(),
                                             outputs_blobseq) &&
             BatchResult::WriteMetadata(result.metadata(), outputs_blobseq) &&
             BatchResult::WriteStats(result.stats(), outputs_blobseq) &&
             BatchResult::WriteInputEnd(outputs_blobseq);
    }
  }

  const SanCovRuntimeRawFeatureParts sancov_features =
      SanCovRuntimeGetFeatures();
  // Copy features to shared memory.
  if (!BatchResult::WriteOneFeatureVec(sancov_features.features,
                                       sancov_features.num_features,
                                       outputs_blobseq)) {
    return false;
  }

  if (!BatchResult::WriteMetadata(SanCovRuntimeGetExecutionMetadata(),
                                  outputs_blobseq)) {
    return false;
  }

  // Write the stats.
  if (!BatchResult::WriteStats(state->stats, outputs_blobseq)) return false;
  // We are done with this input.
  if (!BatchResult::WriteInputEnd(outputs_blobseq)) return false;
  return true;
}

// Handles an ExecutionRequest, see RequestExecution(). Reads inputs from
// `inputs_blobseq`, runs them, saves coverage features to `outputs_blobseq`.
// Returns EXIT_SUCCESS on success and EXIT_FAILURE otherwise.
static int ExecuteInputsFromShmem(BlobSequence &inputs_blobseq,
                                  BlobSequence &outputs_blobseq,
                                  RunnerCallbacks &callbacks) {
  size_t num_inputs = 0;
  if (!IsExecutionRequest(inputs_blobseq.Read())) return EXIT_FAILURE;
  if (!IsNumInputs(inputs_blobseq.Read(), num_inputs)) return EXIT_FAILURE;

  CentipedeBeginExecutionBatch();

  for (size_t i = 0; i < num_inputs; i++) {
    auto blob = inputs_blobseq.Read();
    // TODO(kcc): distinguish bad input from end of stream.
    if (!blob.IsValid()) return EXIT_SUCCESS;  // no more blobs to read.
    if (!IsDataInput(blob)) return EXIT_FAILURE;

    // TODO(kcc): [impl] handle sizes larger than kMaxDataSize.
    size_t size = std::min(kMaxDataSize, blob.size);
    // Copy from blob to data so that to not pass the shared memory further.
    std::vector<uint8_t> data(blob.data, blob.data + size);

    // Starting execution of one more input.
    if (!StartSendingOutputsToEngine(outputs_blobseq)) break;

    RunOneInput(data.data(), data.size(), callbacks);

    if (state->has_failure_description.load()) break;

    if (!FinishSendingOutputsToEngine(outputs_blobseq)) break;
  }

  CentipedeEndExecutionBatch();

  return state->has_failure_description.load() ? EXIT_FAILURE : EXIT_SUCCESS;
}

// Dumps seed inputs to `output_dir`. Also see `GetSeedsViaExternalBinary()`.
static void DumpSeedsToDir(RunnerCallbacks &callbacks, const char *output_dir) {
  size_t seed_index = 0;
  callbacks.GetSeeds([&](ByteSpan seed) {
    // Cap seed index within 9 digits. If this was triggered, the dumping would
    // take forever..
    if (seed_index >= 1000000000) return;
    char seed_path_buf[PATH_MAX];
    const size_t num_path_chars =
        snprintf(seed_path_buf, PATH_MAX, "%s/%09lu", output_dir, seed_index);
    PrintErrorAndExitIf(num_path_chars >= PATH_MAX,
                        "seed path reaches PATH_MAX");
    FILE *output_file = fopen(seed_path_buf, "w");
    const size_t num_bytes_written =
        fwrite(seed.data(), 1, seed.size(), output_file);
    PrintErrorAndExitIf(num_bytes_written != seed.size(),
                        "wrong number of bytes written for cf table");
    fclose(output_file);
    ++seed_index;
  });
}

// Dumps serialized target config to `output_file_path`. Also see
// `GetSerializedTargetConfigViaExternalBinary()`.
static void DumpSerializedTargetConfigToFile(RunnerCallbacks &callbacks,
                                             const char *output_file_path) {
  const std::string config = callbacks.GetSerializedTargetConfig();
  FILE *output_file = fopen(output_file_path, "w");
  const size_t num_bytes_written =
      fwrite(config.data(), 1, config.size(), output_file);
  PrintErrorAndExitIf(
      num_bytes_written != config.size(),
      "wrong number of bytes written for serialized target configuration");
  fclose(output_file);
}

// Returns a random seed. No need for a more sophisticated seed.
// TODO(kcc): [as-needed] optionally pass an external seed.
static unsigned GetRandomSeed() { return time(nullptr); }

// Handles a Mutation Request, see RequestMutation().
// Mutates inputs read from `inputs_blobseq`,
// writes the mutants to `outputs_blobseq`
// Returns EXIT_SUCCESS on success and EXIT_FAILURE on failure
// so that main() can return its result.
// If both `custom_mutator_cb` and `custom_crossover_cb` are nullptr,
// returns EXIT_FAILURE.
//
// TODO(kcc): [impl] make use of custom_crossover_cb, if available.
static int MutateInputsFromShmem(BlobSequence &inputs_blobseq,
                                 BlobSequence &outputs_blobseq,
                                 RunnerCallbacks &callbacks) {
  // Read max_num_mutants.
  size_t num_mutants = 0;
  size_t num_inputs = 0;
  if (!IsMutationRequest(inputs_blobseq.Read())) return EXIT_FAILURE;
  if (!IsNumMutants(inputs_blobseq.Read(), num_mutants)) return EXIT_FAILURE;
  if (!IsNumInputs(inputs_blobseq.Read(), num_inputs)) return EXIT_FAILURE;

  // Mutation input with ownership.
  struct MutationInput {
    ByteArray data;
    ExecutionMetadata metadata;
  };
  // TODO(kcc): unclear if we can continue using std::vector (or other STL)
  // in the runner. But for now use std::vector.
  // Collect the inputs into a vector. We copy them instead of using pointers
  // into shared memory so that the user code doesn't touch the shared memory.
  std::vector<MutationInput> inputs;
  inputs.reserve(num_inputs);
  std::vector<MutationInputRef> input_refs;
  input_refs.reserve(num_inputs);
  for (size_t i = 0; i < num_inputs; ++i) {
    // If inputs_blobseq have overflown in the engine, we still want to
    // handle the first few inputs.
    ExecutionMetadata metadata;
    if (!IsExecutionMetadata(inputs_blobseq.Read(), metadata)) {
      break;
    }
    auto blob = inputs_blobseq.Read();
    if (!IsDataInput(blob)) break;
    inputs.push_back(
        MutationInput{/*data=*/ByteArray{blob.data, blob.data + blob.size},
                      /*metadata=*/std::move(metadata)});
    input_refs.push_back(
        MutationInputRef{/*data=*/inputs.back().data,
                         /*metadata=*/&inputs.back().metadata});
  }

  if (!inputs.empty()) {
    state->byte_array_mutator->SetMetadata(inputs[0].metadata);
  }

  if (!MutationResult::WriteHasCustomMutator(callbacks.HasCustomMutator(),
                                             outputs_blobseq)) {
    return EXIT_FAILURE;
  }
  if (!callbacks.HasCustomMutator()) return EXIT_SUCCESS;

  if (!callbacks.Mutate(input_refs, num_mutants, [&](ByteSpan mutant) {
        MutationResult::WriteMutant(mutant, outputs_blobseq);
      })) {
    return EXIT_FAILURE;
  }
  return EXIT_SUCCESS;
}

bool LegacyRunnerCallbacks::Mutate(
    const std::vector<MutationInputRef> &inputs, size_t num_mutants,
    std::function<void(ByteSpan)> new_mutant_callback) {
  if (custom_mutator_cb_ == nullptr) return false;
  unsigned int seed = GetRandomSeed();
  const size_t num_inputs = inputs.size();
  const size_t max_mutant_size = state->run_time_flags.max_len;
  constexpr size_t kAverageMutationAttempts = 2;
  ByteArray mutant(max_mutant_size);
  for (size_t attempt = 0, num_outputs = 0;
       attempt < num_mutants * kAverageMutationAttempts &&
       num_outputs < num_mutants;
       ++attempt) {
    const auto &input_data = inputs[rand_r(&seed) % num_inputs].data;

    size_t size = std::min(input_data.size(), max_mutant_size);
    std::copy(input_data.cbegin(), input_data.cbegin() + size, mutant.begin());
    size_t new_size = 0;
    if ((custom_crossover_cb_ != nullptr) &&
        rand_r(&seed) % 100 < state->run_time_flags.crossover_level) {
      // Perform crossover `crossover_level`% of the time.
      const auto &other_data = inputs[rand_r(&seed) % num_inputs].data;
      new_size = custom_crossover_cb_(
          input_data.data(), input_data.size(), other_data.data(),
          other_data.size(), mutant.data(), max_mutant_size, rand_r(&seed));
    } else {
      new_size = custom_mutator_cb_(mutant.data(), size, max_mutant_size,
                                    rand_r(&seed));
    }
    if (new_size == 0) continue;
    new_mutant_callback({mutant.data(), new_size});
    ++num_outputs;
  }
  return true;
}

// Returns the current process VmSize, in bytes.
static size_t GetVmSizeInBytes() {
  FILE *f = fopen("/proc/self/statm", "r");  // man proc
  if (!f) return 0;
  size_t vm_size = 0;
  // NOTE: Ignore any (unlikely) failures to suppress a compiler warning.
  (void)fscanf(f, "%zd", &vm_size);
  fclose(f);
  return vm_size * getpagesize();  // proc gives VmSize in pages.
}

// Sets RLIMIT_CORE, RLIMIT_AS
static void SetLimits() {
  // Disable core dumping.
  struct rlimit core_limits;
  getrlimit(RLIMIT_CORE, &core_limits);
  core_limits.rlim_cur = 0;
  core_limits.rlim_max = 0;
  setrlimit(RLIMIT_CORE, &core_limits);

  // ASAN/TSAN/MSAN can not be used with RLIMIT_AS.
  // We get the current VmSize, if it is greater than 1Tb, we assume we
  // are running under one of ASAN/TSAN/MSAN and thus cannot use RLIMIT_AS.
  constexpr size_t one_tb = 1ULL << 40;
  size_t vm_size_in_bytes = GetVmSizeInBytes();
  // Set the address-space limit (RLIMIT_AS).
  // No-op under ASAN/TSAN/MSAN - those may still rely on rss_limit_mb.
  if (vm_size_in_bytes < one_tb) {
    size_t address_space_limit_mb =
        state->flag_helper.HasIntFlag(":address_space_limit_mb=", 0);
    if (address_space_limit_mb > 0) {
      size_t limit_in_bytes = address_space_limit_mb << 20;
      struct rlimit rlimit_as = {limit_in_bytes, limit_in_bytes};
      setrlimit(RLIMIT_AS, &rlimit_as);
    }
  } else {
    fprintf(stderr,
            "Not using RLIMIT_AS; "
            "VmSize is %zdGb, suspecting ASAN/MSAN/TSAN\n",
            vm_size_in_bytes >> 30);
  }
}

// Create a fake reference to ForkServerCallMeVeryEarly() here so that the
// fork server module is not dropped during linking.
// Alternatives are
//  * Use -Wl,--whole-archive when linking with the runner archive.
//  * Use -Wl,-u,ForkServerCallMeVeryEarly when linking with the runner archive.
//    (requires ForkServerCallMeVeryEarly to be extern "C").
// These alternatives require extra flags and are thus more fragile.
// We declare ForkServerCallMeVeryEarly() here instead of doing it in some
// header file, because we want to keep the fork server header-free.
extern void ForkServerCallMeVeryEarly();
[[maybe_unused]] auto fake_reference_for_fork_server =
    &ForkServerCallMeVeryEarly;

void MaybeConnectToPersistentMode() {
  if (state->persistent_mode_socket_path == nullptr) {
    return;
  }
  state->persistent_mode_socket = socket(AF_UNIX, SOCK_STREAM, 0);
  if (state->persistent_mode_socket < 0) {
    fprintf(stderr, "Failed to create persistent mode socket\n");
  }

  struct sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  const size_t socket_path_len = strlen(state->persistent_mode_socket_path);
  RunnerCheck(
      socket_path_len < sizeof(addr.sun_path),
      "persistent mode socket path string must be fit in sockaddr_un.sun_path");
  std::memcpy(addr.sun_path, state->persistent_mode_socket_path,
              socket_path_len);

  int connect_ret = 0;
  do {
    connect_ret = connect(state->persistent_mode_socket,
                          (struct sockaddr*)&addr, sizeof(addr));
  } while (connect_ret == -1 && errno == EINTR);
  if (connect_ret == -1) {
    fprintf(stderr, "Failed to connect the persistent mode socket to %s\n",
            state->persistent_mode_socket_path);
    (void)close(state->persistent_mode_socket);
    state->persistent_mode_socket = -1;
  }

  int flags = fcntl(state->persistent_mode_socket, F_GETFD);
  if (flags == -1) {
    fprintf(stderr, "fcntl(F_GETFD) failed\n");
    (void)close(state->persistent_mode_socket);
    state->persistent_mode_socket = -1;
  }
  flags |= FD_CLOEXEC;
  if (fcntl(state->persistent_mode_socket, F_SETFD, flags) == -1) {
    fprintf(stderr, "fcntl(F_SETFD) failed\n");
    (void)close(state->persistent_mode_socket);
    state->persistent_mode_socket = -1;
  }
}

GlobalRunnerState::GlobalRunnerState() {
  // Make sure fork server is started if needed.
  ForkServerCallMeVeryEarly();

  // Connecting to the persistent mode socket should be immediately after.
  MaybeConnectToPersistentMode();

  SancovRuntimeInitialize();

  // TODO(kcc): move some code from CentipedeRunnerMain() here so that it works
  // even if CentipedeRunnerMain() is not called.
  state->StartWatchdogThread();

  SetLimits();
}

void GlobalRunnerState::OnTermination() {
  // The process is winding down, but CentipedeRunnerMain did not run.
  // This means, the binary is standalone with its own main(), and we need to
  // report the coverage now.
  if (!state->centipede_runner_main_executed &&
      flag_helper.HasFlag(":shmem:")) {
    PostProcessSancov();  // TODO(xinhaoyuan): do we know our exit status?
    SharedMemoryBlobSequence outputs_blobseq(sancov_state->arg2);
    StartSendingOutputsToEngine(outputs_blobseq);
    FinishSendingOutputsToEngine(outputs_blobseq);
  }
  {
    LockGuard lock(state->execution_result_override_mu);
    if (state->execution_result_override != nullptr) {
      delete state->execution_result_override;
      state->execution_result_override = nullptr;
    }
  }
}

static int HandleSharedMemoryRequest(RunnerCallbacks& callbacks,
                                     BlobSequence& inputs_blobseq,
                                     BlobSequence& outputs_blobseq) {
  state->has_failure_description = false;
  // Read the first blob. It indicates what further actions to take.
  auto request_type_blob = inputs_blobseq.Read();
  if (IsMutationRequest(request_type_blob)) {
    // Mutation request.
    inputs_blobseq.Reset();
    static auto mutator = new ByteArrayMutator(state->knobs, GetRandomSeed());
    state->byte_array_mutator = mutator;
    // Since we are mutating, no need to spend time collecting the coverage.
    // We still pay for executing the coverage callbacks, but those will
    // return immediately.
    const int old_traced = CentipedeSetCurrentThreadTraced(/*traced=*/0);
    const int result =
        MutateInputsFromShmem(inputs_blobseq, outputs_blobseq, callbacks);
    CentipedeSetCurrentThreadTraced(old_traced);
    return result;
  }
  if (IsExecutionRequest(request_type_blob)) {
    // Execution request.
    inputs_blobseq.Reset();
    return ExecuteInputsFromShmem(inputs_blobseq, outputs_blobseq, callbacks);
  }
  return EXIT_FAILURE;
}

static int HandlePersistentMode(RunnerCallbacks& callbacks,
                                BlobSequence& inputs_blobseq,
                                BlobSequence& outputs_blobseq) {
  bool first = true;
  while (true) {
    PersistentModeRequest req;
    if (!ReadAll(state->persistent_mode_socket, reinterpret_cast<char*>(&req),
                 1)) {
      perror("Failed to read request from persistent mode socket");
      return EXIT_FAILURE;
    }
    if (first) {
      first = false;
    } else {
      // Reset stdout/stderr.
      for (int fd = 1; fd <= 2; fd++) {
        lseek(fd, 0, SEEK_SET);
        // NOTE: Allow ftruncate() to fail by ignoring its return; that's okay
        // to happen when the stdout/stderr are not redirected to a file.
        (void)ftruncate(fd, 0);
      }
      fprintf(stderr, "Centipede fuzz target runner (%s); flags: %s\n",
              req == PersistentModeRequest::kExit ? "exiting persistent mode"
                                                  : "persistent mode batch",
              state->flag_helper.flags);
    }
    if (req == PersistentModeRequest::kExit) break;
    RunnerCheck(req == PersistentModeRequest::kRunBatch,
                "Unknown persistent mode request");
    const int result =
        HandleSharedMemoryRequest(callbacks, inputs_blobseq, outputs_blobseq);
    inputs_blobseq.Reset();
    outputs_blobseq.Reset();
    if (!WriteAll(state->persistent_mode_socket,
                  reinterpret_cast<const char*>(&result), sizeof(result))) {
      perror("Failed to write response to the persistent mode socket");
      return EXIT_FAILURE;
    }
  }
  return EXIT_SUCCESS;
}

// If HasFlag(:shmem:), state->arg1 and state->arg2 are the names
//  of in/out shared memory locations.
//  Read inputs and write outputs via shared memory.
//
//  Default: Execute ReadOneInputExecuteItAndDumpCoverage() for all inputs.//
//
//  Note: argc/argv are used for only ReadOneInputExecuteItAndDumpCoverage().
int RunnerMain(int argc, char **argv, RunnerCallbacks &callbacks) {
  state->centipede_runner_main_executed = true;

  fprintf(stderr, "Centipede fuzz target runner; argv[0]: %s flags: %s\n",
          argv[0], state->flag_helper.flags);

  if (state->flag_helper.HasFlag(":dump_configuration:")) {
    DumpSerializedTargetConfigToFile(callbacks,
                                     /*output_file_path=*/sancov_state->arg1);
    return EXIT_SUCCESS;
  }

  if (state->flag_helper.HasFlag(":dump_seed_inputs:")) {
    // Seed request.
    DumpSeedsToDir(callbacks, /*output_dir=*/sancov_state->arg1);
    return EXIT_SUCCESS;
  }

  // Inputs / outputs from shmem.
  if (state->flag_helper.HasFlag(":shmem:")) {
    if (!sancov_state->arg1 || !sancov_state->arg2) return EXIT_FAILURE;
    SharedMemoryBlobSequence inputs_blobseq(sancov_state->arg1);
    SharedMemoryBlobSequence outputs_blobseq(sancov_state->arg2);
    // Persistent mode loop.
    if (state->persistent_mode_socket > 0) {
      return HandlePersistentMode(callbacks, inputs_blobseq, outputs_blobseq);
    }
    return HandleSharedMemoryRequest(callbacks, inputs_blobseq,
                                     outputs_blobseq);
  }

  // By default, run every input file one-by-one.
  for (int i = 1; i < argc; i++) {
    ReadOneInputExecuteItAndDumpCoverage(argv[i], callbacks);
  }
  return EXIT_SUCCESS;
}

}  // namespace fuzztest::internal

extern "C" int LLVMFuzzerRunDriver(
    int *absl_nonnull argc, char ***absl_nonnull argv,
    FuzzerTestOneInputCallback test_one_input_cb) {
  if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(argc, argv);
  return RunnerMain(*argc, *argv,
                    *fuzztest::internal::CreateLegacyRunnerCallbacks(
                        test_one_input_cb, LLVMFuzzerCustomMutator,
                        LLVMFuzzerCustomCrossOver));
}

extern "C" void CentipedeSetRssLimit(size_t rss_limit_mb) {
  fprintf(stderr, "CentipedeSetRssLimit: changing rss_limit_mb to %zu\n",
          rss_limit_mb);
  fuzztest::internal::state->run_time_flags.rss_limit_mb = rss_limit_mb;
}

extern "C" void CentipedeSetStackLimit(size_t stack_limit_kb) {
  fprintf(stderr, "CentipedeSetStackLimit: changing stack_limit_kb to %zu\n",
          stack_limit_kb);
  fuzztest::internal::state->run_time_flags.stack_limit_kb = stack_limit_kb;
}

extern "C" void CentipedeSetTimeoutPerInput(uint64_t timeout_per_input) {
  fprintf(stderr,
          "CentipedeSetTimeoutPerInput: changing timeout_per_input to %" PRIu64
          "\n",
          timeout_per_input);
  fuzztest::internal::state->run_time_flags.timeout_per_input =
      timeout_per_input;
}

extern "C" __attribute__((weak)) const char *absl_nullable
CentipedeGetRunnerFlags() {
  if (const char *runner_flags_env = getenv("CENTIPEDE_RUNNER_FLAGS"))
    return strdup(runner_flags_env);
  return nullptr;
}

// TODO: xinhaoyuan - write test for this.
extern "C" const char* absl_nullable GetSancovFlags() {
  return CentipedeGetRunnerFlags();
}

static std::atomic<bool> in_execution_batch = false;

extern "C" void CentipedeBeginExecutionBatch() {
  if (in_execution_batch) {
    fprintf(stderr,
            "CentipedeBeginExecutionBatch called twice without calling "
            "CentipedeEndExecutionBatch in between\n");
    _exit(EXIT_FAILURE);
  }
  in_execution_batch = true;
  fuzztest::internal::PrepareCoverage(/*full_clear=*/true);
}

extern "C" void CentipedeEndExecutionBatch() {
  if (!in_execution_batch) {
    fprintf(stderr,
            "CentipedeEndExecutionBatch called without calling "
            "CentipedeBeginExecutionBatch before\n");
    _exit(EXIT_FAILURE);
  }
  in_execution_batch = false;
  fuzztest::internal::state->input_start_time = 0;
  fuzztest::internal::state->batch_start_time = 0;
}

extern "C" void CentipedePrepareProcessing() {
  fuzztest::internal::PrepareCoverage(/*full_clear=*/!in_execution_batch);
  fuzztest::internal::state->ResetTimers();
}

extern "C" void CentipedeFinalizeProcessing() {
  fuzztest::internal::CheckWatchdogLimits();
  if (fuzztest::internal::state->input_start_time.exchange(0) != 0) {
    fuzztest::internal::PostProcessSancov();
  }
}

extern "C" int CentipedeSetCurrentThreadTraced(int traced) {
  const int old_traced = fuzztest::internal::tls.traced;
  fuzztest::internal::tls.traced = traced;
  return old_traced;
}

extern "C" size_t CentipedeGetExecutionResult(uint8_t *data, size_t capacity) {
  fuzztest::internal::BlobSequence outputs_blobseq(data, capacity);
  if (!fuzztest::internal::StartSendingOutputsToEngine(outputs_blobseq))
    return 0;
  if (!fuzztest::internal::FinishSendingOutputsToEngine(outputs_blobseq))
    return 0;
  return outputs_blobseq.offset();
}

extern "C" size_t CentipedeGetCoverageData(uint8_t *data, size_t capacity) {
  return fuzztest::internal::CopyFeatures(data, capacity);
}

extern "C" void CentipedeSetExecutionResult(const uint8_t *data, size_t size) {
  using fuzztest::internal::state;
  fuzztest::internal::LockGuard lock(state->execution_result_override_mu);
  if (!state->execution_result_override)
    state->execution_result_override = new fuzztest::internal::BatchResult();
  state->execution_result_override->ClearAndResize(1);
  if (data == nullptr) return;
  // Removing const here should be fine as we don't write to `blobseq`.
  fuzztest::internal::BlobSequence blobseq(const_cast<uint8_t *>(data), size);
  state->execution_result_override->Read(blobseq);
  fuzztest::internal::RunnerCheck(
      state->execution_result_override->num_outputs_read() == 1,
      "Failed to set execution result from CentipedeSetExecutionResult");
}

extern "C" void CentipedeSetFailureDescription(const char *description) {
  using fuzztest::internal::state;
  if (state->failure_description_path == nullptr) return;
  if (state->has_failure_description.exchange(true)) return;
  FILE* f = fopen(state->failure_description_path, "w");
  if (f == nullptr) {
    perror("FAILURE: fopen()");
    return;
  }
  const auto len = strlen(description);
  if (fwrite(description, 1, len, f) != len) {
    perror("FAILURE: fwrite()");
  }
  if (fflush(f) != 0) {
    perror("FAILURE: fflush()");
  }
  if (fclose(f) != 0) {
    perror("FAILURE: fclose()");
  }
}
