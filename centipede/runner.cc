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
// the fuzz target (LLVMFuzzerTestOneInput), then dumps the coverage data.
// If the input path is "/path/to/foo",
// the coverage features are dumped to "/path/to/foo-features"
//
// WARNING: please avoid any C++ libraries here, such as Absl and (most of) STL,
// in order to avoid creating new coverage edges in the binary.
#include "./centipede/runner.h"

#include <pthread.h>  // NOLINT: use pthread to avoid extra dependencies.
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <atomic>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <vector>

#include "./centipede/byte_array_mutator.h"
#include "./centipede/defs.h"
#include "./centipede/execution_request.h"
#include "./centipede/execution_result.h"
#include "./centipede/feature.h"
#include "./centipede/runner_dl_info.h"
#include "./centipede/runner_interface.h"
#include "./centipede/runner_utils.h"
#include "./centipede/shared_memory_blob_sequence.h"

__attribute__((
    weak)) extern centipede::feature_t __start___centipede_extra_features;
__attribute__((
    weak)) extern centipede::feature_t __stop___centipede_extra_features;

namespace centipede {

// Use of the fixed init priority allows to call CentipedeRunnerMain
// from constructor functions (CentipedeRunnerMain needs to run after
// state constructor).
// Note: it must run after ForkServerCallMeVeryEarly, see comment there.
GlobalRunnerState state __attribute__((init_priority(200)));
// We use __thread instead of thread_local so that the compiler warns if
// the initializer for `tls` is not a constant expression.
// `tls` thus must not have a CTOR.
// This avoids calls to __tls_init() in hot functions that use `tls`.
__thread ThreadLocalRunnerState tls;

// Tries to write `description` to `state.failure_description_path`.
static void WriteFailureDescription(const char *description) {
  // TODO(b/264715830): Remove I/O error logging once the bug is fixed?
  if (state.failure_description_path == nullptr) return;
  FILE *f = fopen(state.failure_description_path, "w");
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

void ThreadLocalRunnerState::OnThreadStart() {
  LockGuard lock(state.tls_list_mu);
  // Add myself to state.tls_list.
  auto *old_list = state.tls_list;
  tls.next = old_list;
  state.tls_list = &tls;
  if (old_list != nullptr) old_list->prev = &tls;
}

void ThreadLocalRunnerState::OnThreadStop() {
  LockGuard lock(state.tls_list_mu);
  // Remove myself from state.tls_list. The list never
  // becomes empty because the main thread does not call OnThreadStop().
  if (&tls == state.tls_list) {
    state.tls_list = tls.next;
    tls.prev = nullptr;
  } else {
    auto *prev_tls = tls.prev;
    auto *next_tls = tls.next;
    prev_tls->next = next_tls;
    if (next_tls != nullptr) next_tls->prev = prev_tls;
  }
}

static size_t GetPeakRSSMb() {
  struct rusage usage = {};
  if (getrusage(RUSAGE_SELF, &usage) != 0) return 0;
  // On Linux, ru_maxrss is in KiB
  return usage.ru_maxrss >> 10;
}

// Returns the current time in microseconds.
static uint64_t TimeInUsec() {
  struct timeval tv = {};
  constexpr size_t kUsecInSec = 1000000;
  gettimeofday(&tv, nullptr);
  return tv.tv_sec * kUsecInSec + tv.tv_usec;
}

static void CheckWatchdogLimits() {
  const uint64_t curr_time = time(nullptr);
  struct Resource {
    const char *what;
    const char *units;
    uint64_t value;
    uint64_t limit;
    const char *failure;
  };
  const Resource resources[] = {
      {
          .what = "Per-input timeout",
          .units = "sec",
          .value = curr_time - state.input_start_time,
          .limit = state.run_time_flags.timeout_per_input,
          .failure = kExecutionFailurePerInputTimeout.data(),
      },
      {
          .what = "Per-batch timeout",
          .units = "sec",
          .value = curr_time - state.batch_start_time,
          .limit = state.run_time_flags.timeout_per_batch,
          .failure = kExecutionFailurePerBatchTimeout.data(),
      },
      {
          .what = "RSS limit",
          .units = "MB",
          .value = GetPeakRSSMb(),
          .limit = state.run_time_flags.rss_limit_mb,
          .failure = kExecutionFailureRssLimitExceeded.data(),
      },
  };
  for (const auto &resource : resources) {
    if (resource.limit != 0 && resource.value > resource.limit) {
      // Allow only one invocation to handle a failure: needed because we call
      // this function periodically in `WatchdogThread()`, but also call it in
      // `RunOneInput()` after all the work is done.
      static std::atomic<bool> already_handling_failure = false;
      if (!already_handling_failure.exchange(true)) {
        fprintf(stderr,
                "========= %s exceeded: %" PRIu64 " > %" PRIu64
                " (%s); exiting\n",
                resource.what, resource.value, resource.limit, resource.units);
        WriteFailureDescription(resource.failure);
        _exit(EXIT_FAILURE);
      }
    }
  }
}

// Watchdog thread. Periodically checks if it's time to abort due to a
// timeout/OOM.
[[noreturn]] static void *WatchdogThread(void *unused) {
  while (true) {
    sleep(1);

    // No calls to ResetInputTimer() yet: input execution hasn't started.
    if (state.input_start_time == 0) continue;

    CheckWatchdogLimits();
  }
}

void GlobalRunnerState::StartWatchdogThread() {
  if (state.run_time_flags.timeout_per_input == 0 &&
      state.run_time_flags.timeout_per_batch == 0 &&
      state.run_time_flags.rss_limit_mb == 0) {
    return;
  }
  fprintf(stderr,
          "Starting watchdog thread: timeout_per_input: %" PRIu64
          " sec; timeout_per_batch: %" PRIu64 " sec; rss_limit_mb: %" PRIu64
          " MB\n",
          state.run_time_flags.timeout_per_input,
          state.run_time_flags.timeout_per_batch,
          state.run_time_flags.rss_limit_mb);
  pthread_t watchdog_thread;
  pthread_create(&watchdog_thread, nullptr, WatchdogThread, nullptr);
  pthread_detach(watchdog_thread);
}

void GlobalRunnerState::ResetTimers() {
  const auto curr_time = time(nullptr);
  input_start_time = curr_time;
  // batch_start_time is set only once -- just before the first input of the
  // batch is about to start running.
  if (batch_start_time == 0) {
    batch_start_time = curr_time;
  }
}

// Byte array mutation fallback for a custom mutator, as defined here:
// https://github.com/google/fuzzing/blob/master/docs/structure-aware-fuzzing.md
extern "C" size_t LLVMFuzzerMutate(uint8_t *data, size_t size,
                                   size_t max_size) {
  // TODO(kcc): [as-needed] fix the interface mismatch.
  // LLVMFuzzerMutate is an array-based interface (for compatibility reasons)
  // while centipede::ByteArray has a vector-based interface.
  // This incompatibility causes us to do extra allocate/copy per mutation.
  // It may not cause big problems in practice though.
  if (max_size == 0) return 0;  // just in case, not expected to happen.
  if (size == 0) {
    // Don't mutate empty data, just return a 1-byte result.
    data[0] = 0;
    return 1;
  }

  centipede::ByteArray array(data, data + size);
  state.byte_array_mutator->Mutate(array);
  if (array.size() > max_size) {
    array.resize(max_size);
  }
  memcpy(data, array.data(), array.size());
  return array.size();
}

// An arbitrary large size for input data.
static const size_t kMaxDataSize = 1 << 20;

// TODO(ussuri): Move g_features into GlobalRunnerState.
// An arbitrary large size.
static const size_t kMaxFeatures = 1 << 20;
// FeatureArray used to accumulate features from all sources.
static centipede::FeatureArray<kMaxFeatures> g_features;

static void WriteFeaturesToFile(FILE *file,
                                const centipede::feature_t *features,
                                size_t size) {
  if (!size) return;
  auto bytes_written = fwrite(features, 1, sizeof(features[0]) * size, file);
  PrintErrorAndExitIf(bytes_written != size * sizeof(features[0]),
                      "wrong number of bytes written for coverage");
}

// Clears all coverage data.
// All bitsets, counter arrays and such need to be clear before every execution.
// However, clearing them is expensive because they are sparse.
// Instead, we rely on ForEachNonZeroByte() and
// ConcurrentBitSet::ForEachNonZeroBit to clear the bits/bytes after they
// finish iterating.
// We still need to clear all the thread-local data updated during execution.
__attribute__((noinline))  // so that we see it in profile.
static void
PrepareCoverage() {
  if (state.run_time_flags.path_level != 0) {
    state.ForEachTls([](centipede::ThreadLocalRunnerState &tls) {
      tls.path_ring_buffer.clear();
    });
  }
}

// Post-processes all coverage data, puts it all into `g_features`.
// `target_return_value` is the value returned by LLVMFuzzerTestOneInput.
//
// If `target_return_value == -1`, sets `g_features` to empty.  This way,
// the engine will reject any input that causes the target to return -1.
// LibFuzzer supports this return value as of 2022-07:
// https://llvm.org/docs/LibFuzzer.html#rejecting-unwanted-inputs
__attribute__((noinline))  // so that we see it in profile.
static void
PostProcessCoverage(int target_return_value) {
  g_features.clear();

  if (target_return_value == -1) return;

  // Convert counters to features.
  centipede::ForEachNonZeroByte(
      state.pc_counters, state.pc_counters_size, [](size_t idx, uint8_t value) {
        if (state.run_time_flags.use_pc_features) {
          g_features.push_back(
              centipede::feature_domains::kPCs.ConvertToMe(idx));
        }
        if (state.run_time_flags.use_counter_features) {
          g_features.push_back(
              centipede::feature_domains::k8bitCounters.ConvertToMe(
                  centipede::Convert8bitCounterToNumber(idx, value)));
        }
      });

  // Convert data flow bit set to features.
  if (state.run_time_flags.use_dataflow_features) {
    state.data_flow_feature_set.ForEachNonZeroBit([](size_t idx) {
      g_features.push_back(
          centipede::feature_domains::kDataFlow.ConvertToMe(idx));
    });
  }

  // Convert cmp bit set to features.
  if (state.run_time_flags.use_cmp_features) {
    // TODO(kcc): remove cmp_feature_set.
    state.cmp_feature_set.ForEachNonZeroBit([](size_t idx) {
      g_features.push_back(centipede::feature_domains::kCMP.ConvertToMe(idx));
    });
    state.cmp_eq_set.ForEachNonZeroBit([](size_t idx) {
      g_features.push_back(centipede::feature_domains::kCMPEq.ConvertToMe(idx));
    });
    state.cmp_moddiff_set.ForEachNonZeroBit([](size_t idx) {
      g_features.push_back(
          centipede::feature_domains::kCMPModDiff.ConvertToMe(idx));
    });
    state.cmp_hamming_set.ForEachNonZeroBit([](size_t idx) {
      g_features.push_back(
          centipede::feature_domains::kCMPHamming.ConvertToMe(idx));
    });
    state.cmp_difflog_set.ForEachNonZeroBit([](size_t idx) {
      g_features.push_back(
          centipede::feature_domains::kCMPDiffLog.ConvertToMe(idx));
    });
  }

  // Convert path bit set to features.
  if (state.run_time_flags.path_level != 0) {
    state.path_feature_set.ForEachNonZeroBit([](size_t idx) {
      g_features.push_back(
          centipede::feature_domains::kBoundedPath.ConvertToMe(idx));
    });
  }

  // Copy the features from __centipede_extra_features to g_features.
  // Zero features are ignored - we treat them as default (unset) values.
  for (auto *p = state.user_defined_begin; p != state.user_defined_end; ++p) {
    if (auto feature = *p) {
      g_features.push_back(
          centipede::feature_domains::kUserDefined.ConvertToMe(feature));
      *p = 0;  // cleanup for the next iteration.
    }
  }
}

static void RunOneInput(const uint8_t *data, size_t size,
                        FuzzerTestOneInputCallback test_one_input_cb) {
  state.stats = {};
  size_t last_time_usec = 0;
  auto UsecSinceLast = [&last_time_usec]() {
    uint64_t t = centipede::TimeInUsec();
    uint64_t ret_val = t - last_time_usec;
    last_time_usec = t;
    return ret_val;
  };
  UsecSinceLast();
  PrepareCoverage();
  state.stats.prep_time_usec = UsecSinceLast();
  state.ResetTimers();
  int target_return_value = test_one_input_cb(data, size);
  state.stats.exec_time_usec = UsecSinceLast();
  CheckWatchdogLimits();
  PostProcessCoverage(target_return_value);
  state.stats.post_time_usec = UsecSinceLast();
  state.stats.peak_rss_mb = centipede::GetPeakRSSMb();
}

static std::vector<uint8_t> ReadBytesFromFilePath(const char *input_path) {
  FILE *input_file = fopen(input_path, "r");
  RunnerCheck(input_file != nullptr, "can't open the input file");
  struct stat statbuf = {};
  RunnerCheck(fstat(fileno(input_file), &statbuf) == 0, "fstat failed");
  size_t size = statbuf.st_size;
  RunnerCheck(size != 0, "empty file");
  std::vector<uint8_t> data(size);
  auto num_bytes_read = fread(data.data(), 1, data.size(), input_file);
  RunnerCheck(num_bytes_read == data.size(), "read failed");
  RunnerCheck(fclose(input_file) == 0, "fclose failed");
  return data;
}

// Runs one input provided in file `input_path`.
// Produces coverage data in file `input_path`-features.
__attribute__((noinline))  // so that we see it in profile.
static void
ReadOneInputExecuteItAndDumpCoverage(
    const char *input_path, FuzzerTestOneInputCallback test_one_input_cb) {
  // Read the input.
  auto data = ReadBytesFromFilePath(input_path);

  RunOneInput(data.data(), data.size(), test_one_input_cb);

  // Dump features to a file.
  char features_file_path[PATH_MAX];
  snprintf(features_file_path, sizeof(features_file_path), "%s-features",
           input_path);
  FILE *features_file = fopen(features_file_path, "w");
  PrintErrorAndExitIf(features_file == nullptr, "can't open coverage file");
  WriteFeaturesToFile(features_file, g_features.data(), g_features.size());
  fclose(features_file);
}

// Calls centipede::BatchResult::WriteCmpArgs for every CMP arg pair
// found in `cmp_trace`.
// Returns true if all writes succeeded.
// "noinline" so that we see it in a profile, if it becomes hot.
template <typename CmpTrace>
__attribute__((noinline)) bool WriteCmpArgs(
    CmpTrace &cmp_trace, centipede::SharedMemoryBlobSequence &blobseq) {
  bool write_failed = false;
  cmp_trace.ForEachNonZero(
      [&](uint8_t size, const uint8_t *v0, const uint8_t *v1) {
        if (!centipede::BatchResult::WriteCmpArgs(v0, v1, size, blobseq))
          write_failed = true;
      });
  return !write_failed;
}

// Starts sending the outputs (coverage, etc.) to `outputs_blobseq`.
// Returns true on success.
static bool StartSendingOutputsToEngine(
    centipede::SharedMemoryBlobSequence &outputs_blobseq) {
  return centipede::BatchResult::WriteInputBegin(outputs_blobseq);
}

// Finishes sending the outputs (coverage, etc.) to `outputs_blobseq`.
// Returns true on success.
static bool FinishSendingOutputsToEngine(
    centipede::SharedMemoryBlobSequence &outputs_blobseq) {
  // Copy features to shared memory.
  if (!centipede::BatchResult::WriteOneFeatureVec(
          g_features.data(), g_features.size(), outputs_blobseq)) {
    return false;
  }

  // Copy the CMP traces to shared memory.
  if (state.run_time_flags.use_auto_dictionary) {
    bool write_failed = false;
    state.ForEachTls([&write_failed, &outputs_blobseq](
                         centipede::ThreadLocalRunnerState &tls) {
      if (!WriteCmpArgs(tls.cmp_trace2, outputs_blobseq)) write_failed = true;
      if (!WriteCmpArgs(tls.cmp_trace4, outputs_blobseq)) write_failed = true;
      if (!WriteCmpArgs(tls.cmp_trace8, outputs_blobseq)) write_failed = true;
      if (!WriteCmpArgs(tls.cmp_traceN, outputs_blobseq)) write_failed = true;
    });
    if (write_failed) return false;
  }

  // Write the stats.
  if (!centipede::BatchResult::WriteStats(state.stats, outputs_blobseq))
    return false;
  // We are done with this input.
  if (!centipede::BatchResult::WriteInputEnd(outputs_blobseq)) return false;
  return true;
}

// Handles an ExecutionRequest, see RequestExecution(). Reads inputs from
// `inputs_blobseq`, runs them, saves coverage features to `outputs_blobseq`.
// Returns EXIT_SUCCESS on success and EXIT_FAILURE otherwise.
static int ExecuteInputsFromShmem(
    centipede::SharedMemoryBlobSequence &inputs_blobseq,
    centipede::SharedMemoryBlobSequence &outputs_blobseq,
    FuzzerTestOneInputCallback test_one_input_cb) {
  size_t num_inputs = 0;
  if (!execution_request::IsExecutionRequest(inputs_blobseq.Read()))
    return EXIT_FAILURE;
  if (!execution_request::IsNumInputs(inputs_blobseq.Read(), num_inputs))
    return EXIT_FAILURE;
  for (size_t i = 0; i < num_inputs; i++) {
    auto blob = inputs_blobseq.Read();
    // TODO(kcc): distinguish bad input from end of stream.
    if (!blob.IsValid()) return EXIT_SUCCESS;  // no more blobs to read.
    if (!execution_request::IsDataInput(blob)) return EXIT_FAILURE;

    // TODO(kcc): [impl] handle sizes larger than kMaxDataSize.
    size_t size = std::min(kMaxDataSize, blob.size);
    // Copy from blob to data so that to not pass the shared memory further.
    std::vector<uint8_t> data(blob.data, blob.data + size);

    // Starting execution of one more input.
    if (!StartSendingOutputsToEngine(outputs_blobseq)) break;

    RunOneInput(data.data(), data.size(), test_one_input_cb);

    if (!FinishSendingOutputsToEngine(outputs_blobseq)) break;
  }
  return EXIT_SUCCESS;
}

// Dumps the pc table to `output_path`.
// Requires that state.main_object is already computed.
static void DumpPcTable(const char *output_path) {
  PrintErrorAndExitIf(!state.main_object.IsSet(), "main_object is not set");
  FILE *output_file = fopen(output_path, "w");
  PrintErrorAndExitIf(output_file == nullptr, "can't open output file");
  // Make a local copy of the pc table, and subtract the ASLR base
  // (i.e. main_object_start_address) from every PC before dumping the table.
  // Otherwise, we need to pass this ASLR offset at the symbolization time,
  // e.g. via `llvm-symbolizer --adjust-vma=<ASLR offset>`.
  // Another alternative is to build the binary w/o -fPIE or with -static.
  const uintptr_t *data = state.pcs_beg;
  const size_t data_size_in_words = state.pcs_end - state.pcs_beg;
  const size_t data_size_in_bytes = data_size_in_words * sizeof(*state.pcs_beg);
  PrintErrorAndExitIf((data_size_in_words % 2) != 0, "bad data_size_in_words");
  auto *data_copy = new uintptr_t[data_size_in_words];
  for (size_t i = 0; i < data_size_in_words; i += 2) {
    // data_copy is an array of pairs. First element is the pc, which we need to
    // modify. The second element is the pc flags, we just copy it.
    data_copy[i] = data[i] - state.main_object.start_address;
    data_copy[i + 1] = data[i + 1];
  }
  // Dump the modified table.
  auto num_bytes_written =
      fwrite(data_copy, 1, data_size_in_bytes, output_file);
  PrintErrorAndExitIf(num_bytes_written != data_size_in_bytes,
                      "wrong number of bytes written for pc table");
  fclose(output_file);
  delete[] data_copy;
}

// Dumps the control-flow table to `output_path`.
// Requires that state.main_object is already computed.
static void DumpCfTable(const char *output_path) {
  PrintErrorAndExitIf(!state.main_object.IsSet(), "main_object is not set");
  FILE *output_file = fopen(output_path, "w");
  PrintErrorAndExitIf(output_file == nullptr, "can't open output file");
  // Make a local copy of the cf table, and subtract the ASLR base
  // (i.e. main_object.start_address) from every PC before dumping the table.
  // Otherwise, we need to pass this ASLR offset at the symbolization time,
  // e.g. via `llvm-symbolizer --adjust-vma=<ASLR offset>`.
  // Another alternative is to build the binary w/o -fPIE or with -static.
  const uintptr_t *data = state.cfs_beg;
  const size_t data_size_in_words = state.cfs_end - state.cfs_beg;
  PrintErrorAndExitIf(data_size_in_words == 0, "No data in control-flow table");
  const size_t data_size_in_bytes = data_size_in_words * sizeof(*state.cfs_beg);
  std::vector<intptr_t> data_copy(data_size_in_words);
  for (size_t i = 0; i < data_size_in_words; ++i) {
    // data_copy is an array of PCs, except for delimiter (Null) and indirect
    // call indicator (-1).
    if (data[i] != 0 && data[i] != -1ULL)
      data_copy[i] = data[i] - state.main_object.start_address;
    else
      data_copy[i] = data[i];
  }
  // Dump the modified table.
  auto num_bytes_written =
      fwrite(data_copy.data(), 1, data_size_in_bytes, output_file);
  PrintErrorAndExitIf(num_bytes_written != data_size_in_bytes,
                      "wrong number of bytes written for cf table");
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
static int MutateInputsFromShmem(
    SharedMemoryBlobSequence &inputs_blobseq,
    SharedMemoryBlobSequence &outputs_blobseq,
    FuzzerCustomMutatorCallback custom_mutator_cb,
    FuzzerCustomCrossOverCallback custom_crossover_cb) {
  if (custom_mutator_cb == nullptr) return EXIT_FAILURE;
  unsigned int seed = GetRandomSeed();
  // Read max_num_mutants.
  size_t num_mutants = 0;
  size_t num_inputs = 0;
  if (!execution_request::IsMutationRequest(inputs_blobseq.Read()))
    return EXIT_FAILURE;
  if (!execution_request::IsNumMutants(inputs_blobseq.Read(), num_mutants))
    return EXIT_FAILURE;
  if (!execution_request::IsNumInputs(inputs_blobseq.Read(), num_inputs))
    return EXIT_FAILURE;

  // TODO(kcc): unclear if we can continue using std::vector (or other STL)
  // in the runner. But for now use std::vector.
  // Collect the inputs into a vector. We copy them instead of using pointers
  // into shared memory so that the user code doesn't touch the shared memory.
  std::vector<std::vector<uint8_t>> inputs;
  inputs.reserve(num_inputs);
  for (size_t i = 0; i < num_inputs; ++i) {
    auto blob = inputs_blobseq.Read();
    // If inputs_blobseq have overflown in the engine, we still want to
    // handle the first few inputs.
    if (!execution_request::IsDataInput(blob)) break;
    inputs.emplace_back(blob.data, blob.data + blob.size);
  }

  // Use a fixed-sized vector as a scratch.
  constexpr size_t kMaxMutantSize = kMaxDataSize;
  ByteArray mutant(kMaxMutantSize);

  constexpr size_t kAverageMutationAttempts = 2;

  // Produce mutants.
  for (size_t attempt = 0, num_outputs = 0;
       attempt < num_mutants * kAverageMutationAttempts &&
       num_outputs < num_mutants;
       ++attempt) {
    const auto &input = inputs[rand_r(&seed) % num_inputs];

    size_t size = std::min(input.size(), kMaxMutantSize);
    mutant.assign(input.data(), input.data() + size);
    size_t new_size = 0;
    if ((custom_crossover_cb != nullptr) &&
        rand_r(&seed) % 100 < state.run_time_flags.crossover_level) {
      // Perform crossover `crossover_level`% of the time.
      const auto &other = inputs[rand_r(&seed) % num_inputs];
      new_size = custom_crossover_cb(input.data(), input.size(), other.data(),
                                     other.size(), mutant.data(),
                                     kMaxMutantSize, rand_r(&seed));
    } else {
      new_size =
          custom_mutator_cb(mutant.data(), size, kMaxMutantSize, rand_r(&seed));
    }
    if (new_size == 0) continue;
    if (!outputs_blobseq.Write({1 /*unused tag*/, new_size, mutant.data()}))
      break;
    ++num_outputs;
  }
  return EXIT_SUCCESS;
}

// Returns the current process VmSize, in bytes.
static size_t GetVmSizeInBytes() {
  FILE *f = fopen("/proc/self/statm", "r");  // man proc
  if (!f) return 0;
  size_t vm_size = 0;
  // NOTE: Ignore any (unlikely) failures to suppress a compiler warning.
  (void)fscanf(f, "%zd", &vm_size);
  fclose(f);
  return vm_size * getauxval(AT_PAGESZ);  // proc gives VmSize in pages.
}

// Sets RLIMIT_CORE, RLIMIT_AS
static void SetLimits() {
  // no core files anywhere.
  prctl(PR_SET_DUMPABLE, 0);

  // ASAN/TSAN/MSAN can not be used with RLIMIT_AS.
  // We get the current VmSize, if it is greater than 1Tb, we assume we
  // are running under one of ASAN/TSAN/MSAN and thus cannot use RLIMIT_AS.
  constexpr size_t one_tb = 1ULL << 40;
  size_t vm_size_in_bytes = GetVmSizeInBytes();
  // Set the address-space limit (RLIMIT_AS).
  // No-op under ASAN/TSAN/MSAN - those may still rely on rss_limit_mb.
  if (vm_size_in_bytes < one_tb) {
    size_t address_space_limit_mb =
        state.HasFlag(":address_space_limit_mb=", 0);
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

static void MaybePopulateReversePcTable() {
  const char *pcs_file_path = state.GetStringFlag(":pcs_file_path=");
  if (!pcs_file_path) return;
  const auto bytes = ReadBytesFromFilePath(pcs_file_path);
  const uintptr_t *pcs_beg = reinterpret_cast<const uintptr_t *>(bytes.data());
  size_t pcs_size = bytes.size() / sizeof(uintptr_t);
  RunnerCheck(bytes.size() % sizeof(uintptr_t) == 0,
              "pcs_size is not multiple of sizeof(uintptr_t)");
  state.reverse_pc_table.SetFromPCs({pcs_beg, pcs_size});
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
// Same for runner_sancov.cc. Avoids the following situation:
// * weak implementations of sancov callbacks are given in the command line
//   before centipede.a.
// * linker sees them and decides to drop runner_sancov.o.
extern void RunnerSancov();
[[maybe_unused]] auto fake_reference_for_runner_sancov = &RunnerSancov;

GlobalRunnerState::GlobalRunnerState() {
  // TODO(kcc): move some code from CentipedeRunnerMain() here so that it works
  // even if CentipedeRunnerMain() is not called.
  tls.OnThreadStart();
  state.StartWatchdogThread();

  centipede::SetLimits();

  // Compute main_object.
  main_object = GetDlInfo(state.GetStringFlag(":dl_path_suffix="));
  if (!main_object.IsSet()) {
    fprintf(
        stderr,
        "Failed to compute main_object. This may happen"
        " e.g. when instrumented code is in a DSO opened later by dlopen()\n");
  }

  // Dump the pc table, if instructed.
  if (state.HasFlag(":dump_pc_table:")) {
    if (!state.arg1) _exit(EXIT_FAILURE);
    centipede::DumpPcTable(state.arg1);
    _exit(EXIT_SUCCESS);
  }

  // Dump the control-flow table, if instructed.
  if (state.HasFlag(":dump_cf_table:")) {
    if (!state.arg1) _exit(EXIT_FAILURE);
    centipede::DumpCfTable(state.arg1);
    _exit(EXIT_SUCCESS);
  }

  MaybePopulateReversePcTable();

  // initialize the user defined section.
  user_defined_begin =
      &__start___centipede_extra_features;
  user_defined_end =
      &__stop___centipede_extra_features;
  if (user_defined_begin && user_defined_end) {
    fprintf(
        stderr,
        "section(\"__centipede_extra_features\") detected with %zd elements\n",
        user_defined_end - user_defined_begin);
  }
}

GlobalRunnerState::~GlobalRunnerState() {
  // The process is winding down, but CentipedeRunnerMain did not run.
  // This means, the binary is standalone with its own main(), and we need to
  // report the coverage now.
  if (!state.centipede_runner_main_executed && state.HasFlag(":shmem:")) {
    int exit_status = EXIT_SUCCESS;  // TODO(kcc): do we know our exit status?
    PostProcessCoverage(exit_status);
    centipede::SharedMemoryBlobSequence outputs_blobseq(state.arg2);
    StartSendingOutputsToEngine(outputs_blobseq);
    FinishSendingOutputsToEngine(outputs_blobseq);
  }
}

// If HasFlag(:dump_pc_table:), dump the pc table to state.arg1.
//   Used to import the pc table into the caller process.
//
// If HasFlag(:shmem:), state.arg1 and state.arg2 are the names
//  of in/out shared memory locations.
//  Read inputs and write outputs via shared memory.
//
//  Default: Execute ReadOneInputExecuteItAndDumpCoverage() for all inputs.//
//
//  Note: argc/argv are used only for two things:
//    * ReadOneInputExecuteItAndDumpCoverage()
//    * LLVMFuzzerInitialize()
extern "C" int CentipedeRunnerMain(
    int argc, char **argv, FuzzerTestOneInputCallback test_one_input_cb,
    FuzzerInitializeCallback initialize_cb,
    FuzzerCustomMutatorCallback custom_mutator_cb,
    FuzzerCustomCrossOverCallback custom_crossover_cb) {
  state.centipede_runner_main_executed = true;

  fprintf(stderr, "Centipede fuzz target runner; argv[0]: %s flags: %s\n",
          argv[0], state.centipede_runner_flags);

  // All further actions will execute code in the target,
  // so we need to call LLVMFuzzerInitialize.
  if (initialize_cb) {
    initialize_cb(&argc, &argv);
  }

  // Inputs / outputs from shmem.
  if (state.HasFlag(":shmem:")) {
    if (!state.arg1 || !state.arg2) return EXIT_FAILURE;
    SharedMemoryBlobSequence inputs_blobseq(state.arg1);
    SharedMemoryBlobSequence outputs_blobseq(state.arg2);
    // Read the first blob. It indicates what further actions to take.
    auto request_type_blob = inputs_blobseq.Read();
    if (execution_request::IsMutationRequest(request_type_blob)) {
      // Mutation request.
      inputs_blobseq.Reset();
      state.byte_array_mutator =
          new ByteArrayMutator(state.knobs, GetRandomSeed());
      return MutateInputsFromShmem(inputs_blobseq, outputs_blobseq,
                                   custom_mutator_cb, custom_crossover_cb);
    }
    if (execution_request::IsExecutionRequest(request_type_blob)) {
      // Execution request.
      inputs_blobseq.Reset();
      return ExecuteInputsFromShmem(inputs_blobseq, outputs_blobseq,
                                    test_one_input_cb);
    }
    return EXIT_FAILURE;
  }

  // By default, run every input file one-by-one.
  for (int i = 1; i < argc; i++) {
    ReadOneInputExecuteItAndDumpCoverage(argv[i], test_one_input_cb);
  }
  return EXIT_SUCCESS;
}

}  // namespace centipede

extern "C" int LLVMFuzzerRunDriver(
    int *argc, char ***argv, FuzzerTestOneInputCallback test_one_input_cb) {
  return CentipedeRunnerMain(*argc, *argv, test_one_input_cb,
                             LLVMFuzzerInitialize, LLVMFuzzerCustomMutator,
                             LLVMFuzzerCustomCrossOver);
}

extern "C" __attribute__((used)) void CentipedeIsPresent() {}
extern "C" __attribute__((used)) void __libfuzzer_is_present() {}
