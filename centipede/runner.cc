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

#include <pthread.h>  // NOLINT: use pthread to avoid extra dependencies.
#include <sys/auxv.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include <atomic>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <string_view>
#include <vector>

#include "./centipede/byte_array_mutator.h"
#include "./centipede/defs.h"
#include "./centipede/feature.h"
#include "./centipede/foreach_nonzero.h"
#include "./centipede/pc_info.h"
#include "./centipede/runner_dl_info.h"
#include "./centipede/runner_interface.h"
#include "./centipede/runner_request.h"
#include "./centipede/runner_result.h"
#include "./centipede/runner_utils.h"
#include "./centipede/shared_memory_blob_sequence.h"

__attribute__((
    weak)) extern centipede::feature_t __start___centipede_extra_features;
__attribute__((
    weak)) extern centipede::feature_t __stop___centipede_extra_features;

namespace centipede {
namespace {

// Returns the length of the common prefix of `s1` and `s2`, but not more
// than 63. I.e. the returned value is in [0, 64).
size_t LengthOfCommonPrefix(const void *s1, const void *s2, size_t n) {
  const auto *p1 = static_cast<const uint8_t *>(s1);
  const auto *p2 = static_cast<const uint8_t *>(s2);
  static constexpr size_t kMaxLen = 63;
  if (n > kMaxLen) n = kMaxLen;
  for (size_t i = 0; i < n; ++i) {
    if (p1[i] != p2[i]) return i;
  }
  return n;
}

}  // namespace

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

void ThreadLocalRunnerState::TraceMemCmp(uintptr_t caller_pc, const uint8_t *s1,
                                         const uint8_t *s2, size_t n,
                                         bool is_equal) {
  if (state.run_time_flags.use_cmp_features) {
    const uintptr_t pc_offset = caller_pc - state.main_object.start_address;
    const uintptr_t hash =
        centipede::Hash64Bits(pc_offset) ^ tls.path_ring_buffer.hash();
    const size_t lcp = LengthOfCommonPrefix(s1, s2, n);
    // lcp is a 6-bit number.
    state.cmp_feature_set.set((hash << 6) | lcp);
  }
  if (!is_equal && state.run_time_flags.use_auto_dictionary) {
    cmp_traceN.Capture(n, s1, s2);
  }
}

void ThreadLocalRunnerState::OnThreadStart() {
  tls.lowest_sp = tls.top_frame_sp =
      reinterpret_cast<uintptr_t>(__builtin_frame_address(0));
  tls.call_stack.Reset(state.run_time_flags.callstack_level);
  tls.path_ring_buffer.Reset(state.run_time_flags.path_level);
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
  tls.ignore = true;
  state.watchdog_thread_started = true;
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
  // Wait until the watchdog actually starts and initializes itself.
  while (!state.watchdog_thread_started) {
    sleep(0);
  }
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
  state.byte_array_mutator->Mutate(array);
  if (array.size() > max_size) {
    array.resize(max_size);
  }
  memcpy(data, array.data(), array.size());
  return array.size();
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
// All bitsets, counter arrays and such need to be clear before every execution.
// However, clearing them is expensive because they are sparse.
// Instead, we rely on ForEachNonZeroByte() and
// ConcurrentBitSet::ForEachNonZeroBit to clear the bits/bytes after they
// finish iterating.
// We still need to clear all the thread-local data updated during execution.
// If `full_clear==true` clear all coverage anyway - useful to remove the
// coverage accumulated during startup.
__attribute__((noinline))  // so that we see it in profile.
static void
PrepareCoverage(bool full_clear) {
  if (state.run_time_flags.path_level != 0) {
    state.ForEachTls([](ThreadLocalRunnerState &tls) {
      tls.path_ring_buffer.Reset(state.run_time_flags.path_level);
      tls.call_stack.Reset(state.run_time_flags.callstack_level);
      tls.lowest_sp = tls.top_frame_sp;
    });
  }
  // TODO(kcc): do we need to clear tls.cmp_trace2 and others here?
  if (!full_clear) return;
  state.pc_counter_set.ForEachNonZeroByte([](size_t idx, uint8_t value) {});
  if (state.run_time_flags.use_dataflow_features)
    state.data_flow_feature_set.ForEachNonZeroBit([](size_t idx) {});
  if (state.run_time_flags.use_cmp_features) {
    state.cmp_feature_set.ForEachNonZeroBit([](size_t idx) {});
    state.cmp_eq_set.ForEachNonZeroBit([](size_t idx) {});
    state.cmp_moddiff_set.ForEachNonZeroBit([](size_t idx) {});
    state.cmp_hamming_set.ForEachNonZeroBit([](size_t idx) {});
    state.cmp_difflog_set.ForEachNonZeroBit([](size_t idx) {});
  }
  if (state.run_time_flags.path_level != 0)
    state.path_feature_set.ForEachNonZeroBit([](size_t idx) {});
  if (state.run_time_flags.callstack_level != 0)
    state.callstack_set.ForEachNonZeroBit([](size_t idx) {});
  for (auto *p = state.user_defined_begin; p != state.user_defined_end; ++p) {
    *p = 0;
  }
  state.sancov_objects.ClearInlineCounters();
}

// Adds a kPCs and/or k8bitCounters feature to `g_features` based on arguments.
// `idx` is a pc_index.
// `counter_value` (non-zero) is a counter value associated with that PC.
static void AddPcIndxedAndCounterToFeatures(size_t idx, uint8_t counter_value) {
  if (state.run_time_flags.use_pc_features) {
    state.g_features.push_back(feature_domains::kPCs.ConvertToMe(idx));
  }
  if (state.run_time_flags.use_counter_features) {
    state.g_features.push_back(feature_domains::k8bitCounters.ConvertToMe(
        Convert8bitCounterToNumber(idx, counter_value)));
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
  state.g_features.clear();

  if (target_return_value == -1) return;

  // Convert counters to features.
  state.pc_counter_set.ForEachNonZeroByte(
      [](size_t idx, uint8_t value) {
        AddPcIndxedAndCounterToFeatures(idx, value);
      },
      0, state.actual_pc_counter_set_size_aligned);

  // Convert data flow bit set to features.
  if (state.run_time_flags.use_dataflow_features) {
    state.data_flow_feature_set.ForEachNonZeroBit([](size_t idx) {
      state.g_features.push_back(feature_domains::kDataFlow.ConvertToMe(idx));
    });
  }

  // Convert cmp bit set to features.
  if (state.run_time_flags.use_cmp_features) {
    // TODO(kcc): remove cmp_feature_set.
    state.cmp_feature_set.ForEachNonZeroBit([](size_t idx) {
      state.g_features.push_back(feature_domains::kCMP.ConvertToMe(idx));
    });
    state.cmp_eq_set.ForEachNonZeroBit([](size_t idx) {
      state.g_features.push_back(feature_domains::kCMPEq.ConvertToMe(idx));
    });
    state.cmp_moddiff_set.ForEachNonZeroBit([](size_t idx) {
      state.g_features.push_back(feature_domains::kCMPModDiff.ConvertToMe(idx));
    });
    state.cmp_hamming_set.ForEachNonZeroBit([](size_t idx) {
      state.g_features.push_back(feature_domains::kCMPHamming.ConvertToMe(idx));
    });
    state.cmp_difflog_set.ForEachNonZeroBit([](size_t idx) {
      state.g_features.push_back(feature_domains::kCMPDiffLog.ConvertToMe(idx));
    });
  }

  // Convert path bit set to features.
  if (state.run_time_flags.path_level != 0) {
    state.path_feature_set.ForEachNonZeroBit([](size_t idx) {
      state.g_features.push_back(
          feature_domains::kBoundedPath.ConvertToMe(idx));
    });
  }

  // Iterate all threads and get features from TLS data.
  state.ForEachTls([](ThreadLocalRunnerState &tls) {
    if (state.run_time_flags.callstack_level != 0) {
      RunnerCheck(tls.top_frame_sp >= tls.lowest_sp,
                  "bad values of tls.top_frame_sp and tls.lowest_sp");
      size_t sp_diff = tls.top_frame_sp - tls.lowest_sp;
      state.g_features.push_back(
          feature_domains::kCallStack.ConvertToMe(sp_diff));
    }
  });

  if (state.run_time_flags.callstack_level != 0) {
    state.callstack_set.ForEachNonZeroBit([](size_t idx) {
      state.g_features.push_back(feature_domains::kCallStack.ConvertToMe(idx));
    });
  }

  // Copy the features from __centipede_extra_features to g_features.
  // Zero features are ignored - we treat them as default (unset) values.
  for (auto *p = state.user_defined_begin; p != state.user_defined_end; ++p) {
    if (auto user_feature = *p) {
      // User domain ID is upper 32 bits
      feature_t user_domain_id = user_feature >> 32;
      // User feature ID is lower 32 bits.
      feature_t user_feature_id = user_feature & ((1ULL << 32) - 1);
      // There is no hard guarantee how many user domains are actually
      // available. If a user domain ID is out of range, alias it to an existing
      // domain. This is kinder than silently dropping the feature.
      user_domain_id %= std::size(feature_domains::kUserDomains);
      state.g_features.push_back(
          feature_domains::kUserDomains[user_domain_id].ConvertToMe(
              user_feature_id));
      *p = 0;  // cleanup for the next iteration.
    }
  }

  // Iterates all non-zero inline 8-bit counters, if they are present.
  // Calls AddPcIndxedAndCounterToFeatures on non-zero counters and zeroes them.
  if (state.run_time_flags.use_pc_features ||
      state.run_time_flags.use_counter_features) {
    state.sancov_objects.ForEachNonZeroInlineCounter(
        [](size_t idx, uint8_t counter_value) {
          AddPcIndxedAndCounterToFeatures(idx, counter_value);
        });
  }
}

void RunnerCallbacks::GetSeeds(std::function<void(ByteSpan)> seed_callback) {
  seed_callback({0});
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
  state.stats = {};
  size_t last_time_usec = 0;
  auto UsecSinceLast = [&last_time_usec]() {
    uint64_t t = TimeInUsec();
    uint64_t ret_val = t - last_time_usec;
    last_time_usec = t;
    return ret_val;
  };
  UsecSinceLast();
  PrepareCoverage(/*full_clear=*/false);
  state.stats.prep_time_usec = UsecSinceLast();
  state.ResetTimers();
  int target_return_value = callbacks.Execute({data, size}) ? 0 : -1;
  state.stats.exec_time_usec = UsecSinceLast();
  CheckWatchdogLimits();
  PostProcessCoverage(target_return_value);
  state.stats.post_time_usec = UsecSinceLast();
  state.stats.peak_rss_mb = GetPeakRSSMb();
}

template <typename Type>
static std::vector<Type> ReadBytesFromFilePath(const char *input_path) {
  FILE *input_file = fopen(input_path, "r");
  RunnerCheck(input_file != nullptr, "can't open the input file");
  struct stat statbuf = {};
  RunnerCheck(fstat(fileno(input_file), &statbuf) == 0, "fstat failed");
  size_t size_in_bytes = statbuf.st_size;
  RunnerCheck(size_in_bytes != 0, "empty file");
  RunnerCheck((size_in_bytes % sizeof(Type)) == 0,
              "file size is not multiple of the type size");
  std::vector<Type> data(size_in_bytes / sizeof(Type));
  auto num_bytes_read = fread(data.data(), 1, size_in_bytes, input_file);
  RunnerCheck(num_bytes_read == size_in_bytes, "read failed");
  RunnerCheck(fclose(input_file) == 0, "fclose failed");
  return data;
}

// Runs one input provided in file `input_path`.
// Produces coverage data in file `input_path`-features.
__attribute__((noinline))  // so that we see it in profile.
static void
ReadOneInputExecuteItAndDumpCoverage(const char *input_path,
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
  WriteFeaturesToFile(features_file, state.g_features.data(),
                      state.g_features.size());
  fclose(features_file);
}

// Calls ExecutionMetadata::AppendCmpEntry for every CMP arg pair
// found in `cmp_trace`.
// Returns true if all appending succeeded.
// "noinline" so that we see it in a profile, if it becomes hot.
template <typename CmpTrace>
__attribute__((noinline)) bool AppendCmpEntries(CmpTrace &cmp_trace,
                                                ExecutionMetadata &metadata) {
  bool append_failed = false;
  cmp_trace.ForEachNonZero(
      [&](uint8_t size, const uint8_t *v0, const uint8_t *v1) {
        if (!metadata.AppendCmpEntry({v0, size}, {v1, size}))
          append_failed = true;
      });
  return !append_failed;
}

// Starts sending the outputs (coverage, etc.) to `outputs_blobseq`.
// Returns true on success.
static bool StartSendingOutputsToEngine(BlobSequence &outputs_blobseq) {
  return BatchResult::WriteInputBegin(outputs_blobseq);
}

// Finishes sending the outputs (coverage, etc.) to `outputs_blobseq`.
// Returns true on success.
static bool FinishSendingOutputsToEngine(BlobSequence &outputs_blobseq) {
  // Copy features to shared memory.
  if (!BatchResult::WriteOneFeatureVec(
          state.g_features.data(), state.g_features.size(), outputs_blobseq)) {
    return false;
  }

  ExecutionMetadata metadata;
  // Copy the CMP traces to shared memory.
  if (state.run_time_flags.use_auto_dictionary) {
    bool append_failed = false;
    state.ForEachTls([&metadata, &append_failed](ThreadLocalRunnerState &tls) {
      if (!AppendCmpEntries(tls.cmp_trace2, metadata)) append_failed = true;
      if (!AppendCmpEntries(tls.cmp_trace4, metadata)) append_failed = true;
      if (!AppendCmpEntries(tls.cmp_trace8, metadata)) append_failed = true;
      if (!AppendCmpEntries(tls.cmp_traceN, metadata)) append_failed = true;
    });
    if (append_failed) return false;
  }
  if (!BatchResult::WriteMetadata(metadata, outputs_blobseq)) return false;

  // Write the stats.
  if (!BatchResult::WriteStats(state.stats, outputs_blobseq)) return false;
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
  if (!runner_request::IsExecutionRequest(inputs_blobseq.Read()))
    return EXIT_FAILURE;
  if (!runner_request::IsNumInputs(inputs_blobseq.Read(), num_inputs))
    return EXIT_FAILURE;

  PrepareCoverage(/*full_clear=*/true);  // Clear the startup coverage.

  for (size_t i = 0; i < num_inputs; i++) {
    auto blob = inputs_blobseq.Read();
    // TODO(kcc): distinguish bad input from end of stream.
    if (!blob.IsValid()) return EXIT_SUCCESS;  // no more blobs to read.
    if (!runner_request::IsDataInput(blob)) return EXIT_FAILURE;

    // TODO(kcc): [impl] handle sizes larger than kMaxDataSize.
    size_t size = std::min(kMaxDataSize, blob.size);
    // Copy from blob to data so that to not pass the shared memory further.
    std::vector<uint8_t> data(blob.data, blob.data + size);

    // Starting execution of one more input.
    if (!StartSendingOutputsToEngine(outputs_blobseq)) break;

    RunOneInput(data.data(), data.size(), callbacks);

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
  std::vector<PCInfo> pcs = state.sancov_objects.CreatePCTable();
  // Dump the pc table.
  const auto data_size_in_bytes = pcs.size() * sizeof(PCInfo);
  auto num_bytes_written =
      fwrite(pcs.data(), 1, data_size_in_bytes, output_file);
  PrintErrorAndExitIf(num_bytes_written != data_size_in_bytes,
                      "wrong number of bytes written for pc table");
  fclose(output_file);
}

// Dumps the control-flow table to `output_path`.
// Requires that state.main_object is already computed.
static void DumpCfTable(const char *output_path) {
  PrintErrorAndExitIf(!state.main_object.IsSet(), "main_object is not set");
  FILE *output_file = fopen(output_path, "w");
  PrintErrorAndExitIf(output_file == nullptr, "can't open output file");
  std::vector<uintptr_t> data = state.sancov_objects.CreateCfTable();
  size_t data_size_in_bytes = data.size() * sizeof(data[0]);
  // Dump the table.
  auto num_bytes_written =
      fwrite(data.data(), 1, data_size_in_bytes, output_file);
  PrintErrorAndExitIf(num_bytes_written != data_size_in_bytes,
                      "wrong number of bytes written for cf table");
  fclose(output_file);
}

// Dumps a DsoTable as a text file. Each line contains the file path and the
// number of instrumented PCs.
static void DumpDsoTable(const char *output_path) {
  FILE *output_file = fopen(output_path, "w");
  RunnerCheck(output_file != nullptr, "DumpDsoTable: can't open output file");
  DsoTable dso_table = state.sancov_objects.CreateDsoTable();
  for (const auto &entry : dso_table) {
    fprintf(output_file, "%s %zd\n", entry.path.c_str(),
            entry.num_instrumented_pcs);
  }
  fclose(output_file);
}

// Dumps seed inputs to `output_dir`. Also see GetSeedsViaExternalBinary().
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
  if (!runner_request::IsMutationRequest(inputs_blobseq.Read()))
    return EXIT_FAILURE;
  if (!runner_request::IsNumMutants(inputs_blobseq.Read(), num_mutants))
    return EXIT_FAILURE;
  if (!runner_request::IsNumInputs(inputs_blobseq.Read(), num_inputs))
    return EXIT_FAILURE;

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
    if (!runner_request::IsExecutionMetadata(inputs_blobseq.Read(), metadata)) {
      break;
    }
    auto blob = inputs_blobseq.Read();
    if (!runner_request::IsDataInput(blob)) break;
    inputs.push_back({.data = {blob.data, blob.data + blob.size},
                      .metadata = std::move(metadata)});
    input_refs.push_back(
        {.data = inputs.back().data, .metadata = &inputs.back().metadata});
  }

  if (!callbacks.Mutate(input_refs, num_mutants, [&](ByteSpan mutant) {
        outputs_blobseq.Write({1 /*unused tag*/, mutant.size(), mutant.data()});
      }))
    return EXIT_FAILURE;
  return EXIT_SUCCESS;
}

bool LegacyRunnerCallbacks::Mutate(
    const std::vector<MutationInputRef> &inputs, size_t num_mutants,
    std::function<void(ByteSpan)> new_mutant_callback) {
  if (custom_mutator_cb_ == nullptr) return false;
  unsigned int seed = GetRandomSeed();
  const size_t num_inputs = inputs.size();
  constexpr size_t kMaxMutantSize = kMaxDataSize;
  constexpr size_t kAverageMutationAttempts = 2;
  ByteArray mutant(kMaxMutantSize);
  for (size_t attempt = 0, num_outputs = 0;
       attempt < num_mutants * kAverageMutationAttempts &&
       num_outputs < num_mutants;
       ++attempt) {
    const auto &input_data = inputs[rand_r(&seed) % num_inputs].data;

    size_t size = std::min(input_data.size(), kMaxMutantSize);
    std::copy(input_data.cbegin(), input_data.cbegin() + size, mutant.begin());
    size_t new_size = 0;
    if ((custom_crossover_cb_ != nullptr) &&
        rand_r(&seed) % 100 < state.run_time_flags.crossover_level) {
      // Perform crossover `crossover_level`% of the time.
      const auto &other_data = inputs[rand_r(&seed) % num_inputs].data;
      new_size = custom_crossover_cb_(
          input_data.data(), input_data.size(), other_data.data(),
          other_data.size(), mutant.data(), kMaxMutantSize, rand_r(&seed));
    } else {
      new_size = custom_mutator_cb_(mutant.data(), size, kMaxMutantSize,
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
        state.HasIntFlag(":address_space_limit_mb=", 0);
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
  const auto pc_table = ReadBytesFromFilePath<PCInfo>(pcs_file_path);
  state.reverse_pc_table.SetFromPCs(pc_table);
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
// Same for runner_sanitizer.cc.
extern void RunnerSanitizer();
[[maybe_unused]] auto fake_reference_for_runner_sanitizer = &RunnerSanitizer;

GlobalRunnerState::GlobalRunnerState() {
  // TODO(kcc): move some code from CentipedeRunnerMain() here so that it works
  // even if CentipedeRunnerMain() is not called.
  tls.OnThreadStart();
  state.StartWatchdogThread();

  SetLimits();

  // Compute main_object.
  main_object = GetDlInfo(state.GetStringFlag(":dl_path_suffix="));
  if (!main_object.IsSet()) {
    fprintf(
        stderr,
        "Failed to compute main_object. This may happen"
        " e.g. when instrumented code is in a DSO opened later by dlopen()\n");
  }

  // Dump the binary info tables.
  if (state.HasFlag(":dump_binary_info:")) {
    RunnerCheck(state.arg1 && state.arg2 && state.arg3,
                "dump_binary_info requires 3 arguments");
    if (!state.arg1 || !state.arg2 || !state.arg3) _exit(EXIT_FAILURE);
    DumpPcTable(state.arg1);
    DumpCfTable(state.arg2);
    DumpDsoTable(state.arg3);
    _exit(EXIT_SUCCESS);
  }

  MaybePopulateReversePcTable();

  // initialize the user defined section.
  user_defined_begin = &__start___centipede_extra_features;
  user_defined_end = &__stop___centipede_extra_features;
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
    SharedMemoryBlobSequence outputs_blobseq(state.arg2);
    StartSendingOutputsToEngine(outputs_blobseq);
    FinishSendingOutputsToEngine(outputs_blobseq);
  }
}

// If HasFlag(:shmem:), state.arg1 and state.arg2 are the names
//  of in/out shared memory locations.
//  Read inputs and write outputs via shared memory.
//
//  Default: Execute ReadOneInputExecuteItAndDumpCoverage() for all inputs.//
//
//  Note: argc/argv are used for only ReadOneInputExecuteItAndDumpCoverage().
int RunnerMain(int argc, char **argv, RunnerCallbacks &callbacks) {
  state.centipede_runner_main_executed = true;

  fprintf(stderr, "Centipede fuzz target runner; argv[0]: %s flags: %s\n",
          argv[0], state.centipede_runner_flags);

  if (state.HasFlag(":dump_seed_inputs:")) {
    // Seed request.
    DumpSeedsToDir(callbacks, /*output_dir=*/state.arg1);
    return EXIT_SUCCESS;
  }

  // Inputs / outputs from shmem.
  if (state.HasFlag(":shmem:")) {
    if (!state.arg1 || !state.arg2) return EXIT_FAILURE;
    SharedMemoryBlobSequence inputs_blobseq(state.arg1);
    SharedMemoryBlobSequence outputs_blobseq(state.arg2);
    // Read the first blob. It indicates what further actions to take.
    auto request_type_blob = inputs_blobseq.Read();
    if (runner_request::IsMutationRequest(request_type_blob)) {
      // Since we are mutating, no need to spend time collecting the coverage.
      // We still pay for executing the coverage callbacks, but those will
      // return immediately.
      // TODO(kcc): do this more consistently, for all coverage types.
      state.run_time_flags.use_cmp_features = false;
      state.run_time_flags.use_pc_features = false;
      state.run_time_flags.use_dataflow_features = false;
      state.run_time_flags.use_counter_features = false;
      // Mutation request.
      inputs_blobseq.Reset();
      state.byte_array_mutator =
          new ByteArrayMutator(state.knobs, GetRandomSeed());
      return MutateInputsFromShmem(inputs_blobseq, outputs_blobseq, callbacks);
    }
    if (runner_request::IsExecutionRequest(request_type_blob)) {
      // Execution request.
      inputs_blobseq.Reset();
      return ExecuteInputsFromShmem(inputs_blobseq, outputs_blobseq, callbacks);
    }
    return EXIT_FAILURE;
  }

  // By default, run every input file one-by-one.
  for (int i = 1; i < argc; i++) {
    ReadOneInputExecuteItAndDumpCoverage(argv[i], callbacks);
  }
  return EXIT_SUCCESS;
}

}  // namespace centipede

extern "C" int LLVMFuzzerRunDriver(
    int *argc, char ***argv, FuzzerTestOneInputCallback test_one_input_cb) {
  if (LLVMFuzzerInitialize) LLVMFuzzerInitialize(argc, argv);
  return RunnerMain(*argc, *argv,
                    *centipede::CreateLegacyRunnerCallbacks(
                        test_one_input_cb, LLVMFuzzerCustomMutator,
                        LLVMFuzzerCustomCrossOver));
}

extern "C" __attribute__((used)) void CentipedeIsPresent() {}
extern "C" __attribute__((used)) void __libfuzzer_is_present() {}

extern "C" void CentipedeClearExecutionResult() {
  // TODO: full_clear=true is expensive - performance may suffer.
  centipede::PrepareCoverage(/*full_clear=*/true);
}

extern "C" size_t CentipedeGetExecutionResult(uint8_t *data, size_t capacity) {
  centipede::PostProcessCoverage(/*target_return_value=*/0);
  centipede::BlobSequence outputs_blobseq(data, capacity);
  if (!centipede::StartSendingOutputsToEngine(outputs_blobseq)) return 0;
  if (!centipede::FinishSendingOutputsToEngine(outputs_blobseq)) return 0;
  return outputs_blobseq.offset();
}
