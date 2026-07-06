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
#include "absl/types/span.h"
#include "./centipede/byte_array_mutator.h"
#include "./centipede/dispatcher_flag_helper.h"
#include "./centipede/engine_abi.h"
#include "./centipede/engine_worker_abi.h"
#include "./centipede/execution_metadata.h"
#include "./centipede/feature.h"
#include "./centipede/mutation_data.h"
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

class SpinlockGuard {
 public:
  SpinlockGuard(std::atomic<bool>& lock, bool acquire = true) : lock_(lock) {
    if (!acquire) return;
    while (lock.exchange(true)) {
      pthread_yield();
    }
  }

  ~SpinlockGuard() { lock_ = false; }

 private:
  std::atomic<bool>& lock_;
};

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

__attribute__((noinline)) void CheckStackLimit(size_t stack_usage,
                                               bool is_current_stack) {
  static std::atomic_flag stack_limit_exceeded = ATOMIC_FLAG_INIT;
  const size_t stack_limit = state->run_time_flags.stack_limit_kb.load() << 10;
  // Check for the stack limit only if sp is inside the stack region.
  if (stack_limit > 0 && stack_usage > stack_limit) {
    const bool test_not_running = state->input_start_time == 0;
    if (test_not_running && is_current_stack) return;
    if (stack_limit_exceeded.test_and_set()) return;
    fprintf(stderr,
            "========= Stack limit exceeded: %zu"
            " > %zu"
            " (byte) in %s; aborting\n",
            stack_usage, stack_limit,
            is_current_stack ? "the current stack" : "a previous stack");
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

void RunnerCallbacks::GetPresetSeedInputs(
    std::function<void(ByteSpan)> seed_callback) {}

void RunnerCallbacks::GetRandomSeedInput(
    std::function<void(ByteSpan)> seed_callback) {
  seed_callback({0});
}

std::string RunnerCallbacks::GetSerializedTargetConfig() { return ""; }

bool RunnerCallbacks::Mutate(
    absl::Span<const MutationInputRef> /*inputs*/, size_t /*num_mutants*/,
    std::function<void(MutantRef)> /*new_mutant_callback*/) {
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

  bool Mutate(absl::Span<const MutationInputRef> inputs, size_t num_mutants,
              std::function<void(MutantRef)> new_mutant_callback) override;

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

bool LegacyRunnerCallbacks::Mutate(
    absl::Span<const MutationInputRef> inputs, size_t num_mutants,
    std::function<void(MutantRef)> new_mutant_callback) {
  if (custom_mutator_cb_ == nullptr) return false;
  unsigned int seed = GetRandomSeed();
  const size_t num_inputs = inputs.size();
  const size_t max_mutant_size = state->run_time_flags.max_len;
  constexpr size_t kAverageMutationAttempts = 2;
  // Reused across iterations to save memory allocations.
  Mutant mutant;
  for (size_t attempt = 0, num_outputs = 0;
       attempt < num_mutants * kAverageMutationAttempts &&
       num_outputs < num_mutants;
       ++attempt) {
    mutant.origin = rand_r(&seed) % num_inputs;
    const auto& input_data = inputs[mutant.origin].data;

    size_t size = std::min(input_data.size(), max_mutant_size);
    mutant.data.resize(max_mutant_size);
    std::copy(input_data.cbegin(), input_data.cbegin() + size,
              mutant.data.begin());
    size_t new_size = 0;
    if ((custom_crossover_cb_ != nullptr) &&
        rand_r(&seed) % 100 < state->run_time_flags.crossover_level) {
      // Perform crossover `crossover_level`% of the time.
      const auto &other_data = inputs[rand_r(&seed) % num_inputs].data;
      new_size = custom_crossover_cb_(input_data.data(), input_data.size(),
                                      other_data.data(), other_data.size(),
                                      mutant.data.data(), max_mutant_size,
                                      rand_r(&seed));
    } else {
      new_size = custom_mutator_cb_(mutant.data.data(), size, max_mutant_size,
                                    rand_r(&seed));
    }
    if (new_size == 0) continue;
    if (new_size > max_mutant_size) new_size = max_mutant_size;
    mutant.data.resize(new_size);
    new_mutant_callback(MutantRef{mutant});
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

GlobalRunnerState::GlobalRunnerState() {
  // Make sure fork server is started if needed.
  ForkServerCallMeVeryEarly();

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

  struct Input {
    ByteArray content;
    ExecutionMetadata metadata;
  };
  // TODO: move it to ctx.
  static bool need_full_cleanup = true;
  FuzzTestAdapterManager manager = {
      /*ctx=*/reinterpret_cast<FuzzTestAdapterManagerCtx*>(&callbacks),
      /*GetBinaryId=*/nullptr,
      /*GetTestName=*/
      [](FuzzTestAdapterManagerCtx* ctx, const FuzzTestBytesSink* sink) {
        // Provide the test name exactly specified from the flag. This should be
        // fine as the user of runner should call RunnerMain at most once.
        static const char* test_name =
            state->flag_helper.GetStringFlag(":test=");
        if (test_name == nullptr) return;
        static size_t len = strlen(test_name);
        const auto bytes = FuzzTestBytesView{
            reinterpret_cast<const uint8_t*>(test_name),
            len,
        };
        sink->Emit(sink->ctx, &bytes);
      },
      /*ConstructAdapter=*/
      [](FuzzTestAdapterManagerCtx* ctx,
         const FuzzTestDiagnosticSink* diagnostic_sink,
         FuzzTestAdapter* adapter_out) {
        {
          SpinlockGuard guard(state->diagnostic_sink_spinlock);
          state->diagnostic_sink = diagnostic_sink;
        }
        adapter_out->ctx = reinterpret_cast<FuzzTestAdapterCtx*>(ctx);
        adapter_out->SetUpCoverageDomains =
            [](FuzzTestAdapterCtx* ctx,
               const FuzzTestCoverageDomainRegistry* registry) {
              SanCovRuntimeSetUpCoverageDomains(registry);
            };
        adapter_out->GetPresetSeedInputs = [](FuzzTestAdapterCtx* ctx,
                                              const FuzzTestInputSink* sink) {
          auto* callbacks = reinterpret_cast<RunnerCallbacks*>(ctx);
          callbacks->GetPresetSeedInputs([&](ByteSpan input) {
            sink->Emit(
                sink->ctx,
                reinterpret_cast<FuzzTestInputHandle>(new Input{
                    /*content=*/{input.data(), input.data() + input.size()},
                    /*metadata=*/{}}));
          });
        };
        adapter_out->GetRandomSeedInput = [](FuzzTestAdapterCtx* ctx,
                                             const FuzzTestInputSink* sink) {
          auto* callbacks = reinterpret_cast<RunnerCallbacks*>(ctx);
          callbacks->GetRandomSeedInput([&](ByteSpan input) {
            sink->Emit(
                sink->ctx,
                reinterpret_cast<FuzzTestInputHandle>(new Input{
                    /*content=*/{input.data(), input.data() + input.size()},
                    /*metadata=*/{}}));
          });
        };
        adapter_out->Mutate = [](FuzzTestAdapterCtx* ctx,
                                 FuzzTestInputHandle origin_handle, int shrink,
                                 const FuzzTestInputSink* sink) {
          need_full_cleanup = true;
          auto* callbacks = reinterpret_cast<RunnerCallbacks*>(ctx);
          const auto* origin = reinterpret_cast<Input*>(origin_handle);
          const auto mutation_input = MutationInputRef{
              origin->content,
              &origin->metadata,
          };
          callbacks->Mutate({&mutation_input, 1}, 1, [&](MutantRef mutant_ref) {
            auto* mutant = new Input{
                /*content=*/{mutant_ref.data.data(),
                             mutant_ref.data.data() + mutant_ref.data.size()},
                /*metadata=*/{},
            };
            sink->Emit(sink->ctx,
                       reinterpret_cast<FuzzTestInputHandle>(mutant));
          });
        };
        adapter_out->Execute = [](FuzzTestAdapterCtx* ctx,
                                  FuzzTestInputHandle handle,
                                  const FuzzTestFeedbackSink* sink) {
          auto* callbacks = reinterpret_cast<RunnerCallbacks*>(ctx);
          auto* input = reinterpret_cast<Input*>(handle);
          if (need_full_cleanup) {
            SanCovRuntimeClearCoverage(true);
            need_full_cleanup = false;
          }
          const int old_traced = CentipedeSetCurrentThreadTraced(/*traced=*/1);
          RunOneInput(input->content.data(), input->content.size(), *callbacks);
          CentipedeSetCurrentThreadTraced(old_traced);
          {
            LockGuard lock(state->execution_result_override_mu);
            bool has_overridden_execution_result = false;
            if (state->execution_result_override != nullptr) {
              RunnerCheck(
                  state->execution_result_override->results().size() <= 1,
                  "unexpected number of overridden execution results");
              has_overridden_execution_result =
                  state->execution_result_override->results().size() == 1;
            }
            if (has_overridden_execution_result) {
              auto& result = state->execution_result_override->results()[0];
              SanCovRuntimeConvertToEngineFeatures(
                  result.mutable_features().data(),
                  result.mutable_features().size());
              const FuzzTestUint64sView features = {
                  result.features().data(),
                  result.features().size(),
              };
              sink->EmitCoverageFeatures(sink->ctx, &features);
              input->metadata = result.metadata();
              return;
            }
          }
          SanCovRuntimeEmitFeatures(sink);
          input->metadata = SanCovRuntimeGetExecutionMetadata();
        };
        adapter_out->DeserializeInputContent =
            [](FuzzTestAdapterCtx* ctx, const FuzzTestBytesView* view,
               const FuzzTestInputSink* sink) {
              auto* input = new Input{
                  /*content=*/{view->data, view->data + view->size},
                  /*metadata=*/{},
              };
              sink->Emit(sink->ctx,
                         reinterpret_cast<FuzzTestInputHandle>(input));
            };
        adapter_out->UpdateInputMetadata = [](FuzzTestAdapterCtx* ctx,
                                              const FuzzTestBytesView* view,
                                              FuzzTestInputHandle handle) {
          auto* input = reinterpret_cast<Input*>(handle);
          input->metadata.cmp_data = {view->data, view->data + view->size};
        };
        adapter_out->SerializeInputContent = [](FuzzTestAdapterCtx* ctx,
                                                FuzzTestInputHandle handle,
                                                const FuzzTestBytesSink* sink) {
          auto* input = reinterpret_cast<Input*>(handle);
          const auto input_bytes = FuzzTestBytesView{
              reinterpret_cast<const uint8_t*>(input->content.data()),
              input->content.size(),
          };
          sink->Emit(sink->ctx, &input_bytes);
        };
        adapter_out->SerializeInputMetadata =
            [](FuzzTestAdapterCtx* ctx, FuzzTestInputHandle handle,
               const FuzzTestBytesSink* sink) {
              auto* input = reinterpret_cast<Input*>(handle);
              const auto input_bytes = FuzzTestBytesView{
                  reinterpret_cast<const uint8_t*>(
                      input->metadata.cmp_data.data()),
                  input->metadata.cmp_data.size(),
              };
              sink->Emit(sink->ctx, &input_bytes);
            };
        adapter_out->FreeInput = [](FuzzTestAdapterCtx* ctx,
                                    FuzzTestInputHandle handle) {
          delete reinterpret_cast<Input*>(handle);
        };
        adapter_out->FreeCtx = [](FuzzTestAdapterCtx* ctx) {
          {
            SpinlockGuard guard(state->diagnostic_sink_spinlock);
            state->diagnostic_sink = nullptr;
          }
        };
      },
  };
  const int old_traced = CentipedeSetCurrentThreadTraced(/*traced=*/0);
  const auto s = FuzzTestWorkerMaybeRun(&manager);
  CentipedeSetCurrentThreadTraced(old_traced);
  if (s == kFuzzTestWorkerNotRequired) {
    // By default, run every input file one-by-one.
    for (int i = 1; i < argc; i++) {
      ReadOneInputExecuteItAndDumpCoverage(argv[i], callbacks);
    }
    return EXIT_SUCCESS;
  }
  return s == kFuzzTestWorkerSuccess ? EXIT_SUCCESS : EXIT_FAILURE;
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
  std::string_view desc_sv = description;
  static constexpr std::string_view kInputFailurePrefix = "INPUT FAILURE:";
  static constexpr std::string_view kIgnoredFailurePrefix = "IGNORED FAILURE:";
  static constexpr std::string_view kSetupFailurePrefix = "SETUP FAILURE:";
  static constexpr std::string_view kSkippedTestPrefix = "SKIPPED TEST:";
  using ::fuzztest::internal::SpinlockGuard;
  using ::fuzztest::internal::state;
  if (desc_sv.substr(0, kIgnoredFailurePrefix.size()) ==
          kIgnoredFailurePrefix ||
      desc_sv.substr(0, kSkippedTestPrefix.size()) == kSkippedTestPrefix) {
    // Nothing to do.
  } else if (desc_sv.substr(0, kSetupFailurePrefix.size()) ==
             kSetupFailurePrefix) {
    const bool try_lock_result =
        !state->diagnostic_sink_spinlock.exchange(true);
    if (try_lock_result) {
      SpinlockGuard guard(state->diagnostic_sink_spinlock, /*acquire=*/false);
      const auto* diagnostic_sink = state->diagnostic_sink;
      const FuzzTestBytesView error = {
          reinterpret_cast<const uint8_t*>(desc_sv.data() +
                                           kSetupFailurePrefix.size()),
          desc_sv.size() - kSetupFailurePrefix.size(),
      };
      diagnostic_sink->EmitError(diagnostic_sink->ctx, &error);
      return;
    }
    std::_Exit(EXIT_FAILURE);
  } else {
    if (desc_sv.substr(0, kInputFailurePrefix.size()) == kInputFailurePrefix) {
      desc_sv = desc_sv.substr(kInputFailurePrefix.size());
    }
    const bool try_lock_result =
        !state->diagnostic_sink_spinlock.exchange(true);
    if (try_lock_result) {
      SpinlockGuard guard(state->diagnostic_sink_spinlock, /*acquire=*/false);
      const auto* diagnostic_sink = state->diagnostic_sink;
      if (diagnostic_sink != nullptr) {
        const FuzzTestBytesView finding_desc = {
            reinterpret_cast<const uint8_t*>(desc_sv.data()),
            desc_sv.size(),
        };
        diagnostic_sink->EmitFinding(diagnostic_sink->ctx, &finding_desc,
                                     &finding_desc);
        return;
      }
    }
    std::_Exit(EXIT_FAILURE);
  }
}
