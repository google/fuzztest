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

#include "./framework_shared/internal/sancov_state.h"

#include <pthread.h>
#include <sys/stat.h>
#include <unistd.h>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <vector>

#include "absl/base/nullability.h"
#include "./centipede/feature.h"
#include "./centipede/pc_info.h"
#include "./framework_shared/internal/execution_metadata.h"
#include "./framework_shared/internal/int_utils.h"
#include "./framework_shared/internal/runner_dl_info.h"
#include "./framework_shared/internal/sancov_utils.h"

__attribute__((weak)) extern fuzztest::internal::feature_t
    __start___centipede_extra_features;
__attribute__((weak)) extern fuzztest::internal::feature_t
    __stop___centipede_extra_features;

// May be updated by sancov with -fsanitize-coverage=stack-depth.
__attribute__((visibility("default")))
__attribute__((weak)) thread_local uintptr_t __sancov_lowest_stack;

namespace fuzztest::internal {

// Weak dummy definition of LSan interface in case LSan is missing.
__attribute__((weak)) void __lsan_register_root_region(const void* p,
                                                       size_t size) {}

ExplicitLifetime<SancovState> sancov_state;
std::atomic<StackLimitCallback> stack_limit_callback{nullptr};

namespace {

// Returns the length of the common prefix of `s1` and `s2`, but not more
// than 63. I.e. the returned value is in [0, 64).
//
// Must not be sanitized because sanitizers may trigger this on unsanitized
// data, causing false positives and nested failures.
FUZZTEST_NO_SANITIZE size_t LengthOfCommonPrefix(const void* s1, const void* s2,
                                                 size_t n) {
  const auto *p1 = static_cast<const uint8_t *>(s1);
  const auto *p2 = static_cast<const uint8_t *>(s2);
  static constexpr size_t kMaxLen = feature_domains::kCMPScoreBitmask;
  if (n > kMaxLen) n = kMaxLen;
  for (size_t i = 0; i < n; ++i) {
    if (p1[i] != p2[i]) return i;
  }
  return n;
}

// Returns the lower bound of the stack region for the current thread. 0 will be
// returned on failures.
uintptr_t GetCurrentThreadStackRegionLow() {
#ifdef __APPLE__
  pthread_t self = pthread_self();
  const auto stack_addr =
      reinterpret_cast<uintptr_t>(pthread_get_stackaddr_np(self));
  const auto stack_size = pthread_get_stacksize_np(self);
  return stack_addr - stack_size;
#else   // __APPLE__
  pthread_attr_t attr = {};
  if (pthread_getattr_np(pthread_self(), &attr) != 0) {
    fprintf(stderr, "Failed to get the pthread attr of the current thread.\n");
    return 0;
  }
  void* stack_addr = nullptr;
  size_t stack_size = 0;
  if (pthread_attr_getstack(&attr, &stack_addr, &stack_size) != 0) {
    fprintf(stderr, "Failed to get the stack region of the current thread.\n");
    pthread_attr_destroy(&attr);
    return 0;
  }
  pthread_attr_destroy(&attr);
  const auto stack_region_low = reinterpret_cast<uintptr_t>(stack_addr);
  SANCOV_CHECK(stack_region_low != 0,
               "the current thread stack region starts from 0 - unexpected!");
  return stack_region_low;
#endif  // __APPLE__
}

class ThreadTerminationDetector {
 public:
  // A dummy method to trigger the construction and make sure that the
  // destructor will be called on the thread termination.
  __attribute__((optnone)) void EnsureAlive() {}

  ~ThreadTerminationDetector() { tls.OnThreadStop(); }
};

thread_local ThreadTerminationDetector termination_detector;

}  // namespace

// We use __thread instead of thread_local so that the compiler warns if
// the initializer for `tls` is not a constant expression.
// `tls` thus must not have a CTOR.
// This avoids calls to __tls_init() in hot functions that use `tls`.
__thread ThreadLocalSancovState tls;

void ThreadLocalSancovState::TraceMemCmp(uintptr_t caller_pc, const uint8_t *s1,
                                         const uint8_t *s2, size_t n,
                                         bool is_equal) {
  if (sancov_state->flags.use_cmp_features) {
    const uintptr_t pc_offset =
        caller_pc - sancov_state->main_object.start_address;
    const uintptr_t hash =
        fuzztest::internal::Hash64Bits(pc_offset) ^ tls.path_ring_buffer.hash();
    const size_t lcp = LengthOfCommonPrefix(s1, s2, n);
    if (is_equal) {
      sancov_state->cmp_eq_set.set(hash);
    } else {
      // lcp is within feature_domains::kCMPScoreBits.
      sancov_state->cmp_moddiff_set.set(
          (hash << feature_domains::kCMPScoreBits) | lcp);
    }
  }
  if (!is_equal && sancov_state->flags.use_auto_dictionary) {
    cmp_traceN.Capture(n, s1, s2);
  }
}

void ThreadLocalSancovState::OnThreadStart() {
  if (tls.started) return;
  termination_detector.EnsureAlive();
  tls.started = true;
  // Always trace threads by default. Internal threads that do not want tracing
  // will set this to false later.
  tls.traced = true;
  tls.sancov_lowest_sp = &__sancov_lowest_stack;
  *tls.sancov_lowest_sp = tls.lowest_sp = tls.top_frame_sp =
      reinterpret_cast<uintptr_t>(__builtin_frame_address(0));
  tls.stack_region_low = GetCurrentThreadStackRegionLow();
  if (tls.stack_region_low == 0) {
    fprintf(stderr,
            "Disabling stack limit check due to missing stack region info.\n");
  }
  tls.call_stack.Reset(sancov_state->flags.callstack_level);
  tls.path_ring_buffer.Reset(sancov_state->flags.path_level);
  LockGuard lock(sancov_state->tls_list_mu);
  // Add myself to state.tls_list.
  auto* old_list = sancov_state->tls_list;
  tls.next = old_list;
  sancov_state->tls_list = &tls;
  if (old_list != nullptr) old_list->prev = &tls;
}

void ThreadLocalSancovState::OnThreadStop() {
  if (tls.sancov_lowest_sp == nullptr) {
    // This can happen only before OnTheadStart() or after OnThreadStop() -
    // nothing to do if that's the case.
    return;
  }
  tls.traced = false;
  LockGuard lock(sancov_state->tls_list_mu);
  const size_t sancov_lowest_sp = *tls.sancov_lowest_sp;
  tls.sancov_lowest_sp = nullptr;
  if (sancov_lowest_sp <= tls.top_frame_sp &&
      sancov_lowest_sp < tls.lowest_sp &&
      sancov_lowest_sp >= tls.stack_region_low && tls.stack_region_low > 0) {
    tls.lowest_sp = sancov_lowest_sp;
  }
  // Remove myself from state.tls_list. The list never
  // becomes empty because the main thread does not call OnThreadStop().
  if (&tls == sancov_state->tls_list) {
    sancov_state->tls_list = tls.next;
    tls.prev = nullptr;
  } else if (tls.prev == nullptr) {
    // The current thread is not linked into the global list, probably due to
    // OnThreadStart not called from untracked pthread_create.
    return;
  } else {
    auto *prev_tls = tls.prev;
    auto *next_tls = tls.next;
    prev_tls->next = next_tls;
    if (next_tls != nullptr) next_tls->prev = prev_tls;
  }
  tls.next = tls.prev = nullptr;
  if (tls.ignore) return;
  // Create a detached copy on heap and add it to detached_tls_list to
  // collect its coverage later.
  //
  // TODO(xinhaoyuan): Consider refactoring the list operations into class
  // methods instead of duplicating them.
  ThreadLocalSancovState *detached_tls = new ThreadLocalSancovState(tls);
  detached_tls->detached = true;
  auto* old_list = sancov_state->detached_tls_list;
  detached_tls->next = old_list;
  sancov_state->detached_tls_list = detached_tls;
  if (old_list != nullptr) old_list->prev = detached_tls;
}

void SancovState::CleanUpDetachedTls() {
  LockGuard lock(tls_list_mu);
  ThreadLocalSancovState *it_next = nullptr;
  for (auto *it = detached_tls_list; it; it = it_next) {
    it_next = it->next;
    delete it;
  }
  detached_tls_list = nullptr;
}

static void MaybePopulateReversePcTable() {
  const char* pcs_file_path =
      sancov_state->flag_helper.GetStringFlag("pcs_file_path=");
  if (!pcs_file_path) return;
  FILE* pcs_file = fopen(pcs_file_path, "rb");
  SANCOV_CHECK(pcs_file != nullptr, "can't open the pcs file");
  struct stat statbuf = {};
  SANCOV_CHECK(fstat(fileno(pcs_file), &statbuf) == 0, "fstat failed");
  const size_t size_in_bytes = statbuf.st_size;
  SANCOV_CHECK(size_in_bytes != 0, "empty file");
  SANCOV_CHECK((size_in_bytes % sizeof(PCInfo)) == 0,
               "file size is not multiple of PCInfo size");
  std::vector<PCInfo> pc_table(size_in_bytes / sizeof(PCInfo));
  const size_t num_bytes_read =
      fread(pc_table.data(), 1, size_in_bytes, pcs_file);
  SANCOV_CHECK(num_bytes_read == size_in_bytes, "read failed");
  SANCOV_CHECK(fclose(pcs_file) == 0, "fclose failed");
  sancov_state->reverse_pc_table.SetFromPCs(pc_table);
}

// Dumps the pc table to `output_path`.
// Requires that state.main_object is already computed.
static void DumpPcTable(const char *absl_nonnull output_path) {
  SANCOV_CHECK(sancov_state->main_object.IsSet(), "main_object is not set");
  FILE *output_file = fopen(output_path, "w");
  SANCOV_CHECK(output_file != nullptr, "can't open output file");
  std::vector<PCInfo> pcs = sancov_state->sancov_objects.CreatePCTable();
  // Dump the pc table.
  const auto data_size_in_bytes = pcs.size() * sizeof(PCInfo);
  auto num_bytes_written =
      fwrite(pcs.data(), 1, data_size_in_bytes, output_file);
  SANCOV_CHECK(num_bytes_written == data_size_in_bytes,
               "wrong number of bytes written for pc table");
  fclose(output_file);
}

// Dumps the control-flow table to `output_path`.
// Requires that state.main_object is already computed.
static void DumpCfTable(const char *absl_nonnull output_path) {
  SANCOV_CHECK(sancov_state->main_object.IsSet(), "main_object is not set");
  FILE *output_file = fopen(output_path, "w");
  SANCOV_CHECK(output_file != nullptr, "can't open output file");
  std::vector<uintptr_t> data = sancov_state->sancov_objects.CreateCfTable();
  size_t data_size_in_bytes = data.size() * sizeof(data[0]);
  // Dump the table.
  auto num_bytes_written =
      fwrite(data.data(), 1, data_size_in_bytes, output_file);
  SANCOV_CHECK(num_bytes_written == data_size_in_bytes,
               "wrong number of bytes written for cf table");
  fclose(output_file);
}

// Dumps a DsoTable as a text file. Each line contains the file path and the
// number of instrumented PCs.
static void DumpDsoTable(const char *absl_nonnull output_path) {
  FILE *output_file = fopen(output_path, "w");
  SANCOV_CHECK(output_file != nullptr, "DumpDsoTable: can't open output file");
  DsoTable dso_table = sancov_state->sancov_objects.CreateDsoTable();
  for (const auto &entry : dso_table) {
    fprintf(output_file, "%s %zd\n", entry.path.c_str(),
            entry.num_instrumented_pcs);
  }
  fclose(output_file);
}

SancovState::SancovState(const char* absl_nullable sancov_flags)
    : flag_helper(sancov_flags) {
  tls.OnThreadStart();
  // Compute main_object.
  main_object = GetDlInfo(flag_helper.GetStringFlag("dl_path_suffix="));
  if (!main_object.IsSet()) {
    fprintf(
        stderr,
        "Failed to compute main_object. This may happen"
        " e.g. when instrumented code is in a DSO opened later by dlopen()\n");
  }

  // Dump the binary info tables.
  if (flag_helper.HasSwitchFlag("dump_binary_info")) {
    SANCOV_CHECK(arg1 && arg2 && arg3, "dump_binary_info requires 3 arguments");
    DumpPcTable(arg1);
    DumpCfTable(arg2);
    DumpDsoTable(arg3);
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

SancovState::~SancovState() {
  // Always clean up detached TLSs to avoid leakage.
  CleanUpDetachedTls();
}

// Avoids the following situation:
// * weak implementations of sancov callbacks are given in the command line
//   before centipede.a.
// * linker sees them and decides to drop sancov_callbacks.o.
extern void Sancov();
[[maybe_unused]] auto fake_reference_for_sancov = &Sancov;
// Same for runtime_interceptors.cc and coverage_interceptors.cc.
extern void RuntimeInterceptor();
[[maybe_unused]] auto fake_reference_for_runtime_interceptor =
    &RuntimeInterceptor;
#ifndef FUZZTEST_REPLAY
extern void CoverageInterceptor();
[[maybe_unused]] auto fake_reference_for_coverage_interceptor =
    &CoverageInterceptor;
#endif  // FUZZTEST_REPLAY

static void MaybeAddFeature(feature_t feature) {
  if (!sancov_state->flags.skip_seen_features) {
    sancov_state->g_features.push_back(feature);
  } else if (!sancov_state->seen_features.get(feature)) {
    sancov_state->g_features.push_back(feature);
    sancov_state->seen_features.set(feature);
  }
}

void CleanUpSancovTls() {
  sancov_state->CleanUpDetachedTls();
  sancov_state->ForEachTls([](ThreadLocalSancovState& tls) {
    if (tls.detached) return;
    if (sancov_state->flags.path_level != 0) {
      tls.path_ring_buffer.Reset(sancov_state->flags.path_level);
    }
    if (sancov_state->flags.callstack_level != 0) {
      tls.call_stack.Reset(sancov_state->flags.callstack_level);
    }
    if (sancov_state->flags.use_auto_dictionary) {
      tls.cmp_trace2.Clear();
      tls.cmp_trace4.Clear();
      tls.cmp_trace8.Clear();
      tls.cmp_traceN.Clear();
    }
    SANCOV_CHECK(tls.sancov_lowest_sp != nullptr,
                 "sancov_lowest_sp is null for a live thread");
    *tls.sancov_lowest_sp = tls.lowest_sp = tls.top_frame_sp;
  });
}

void PrepareSancov(bool full_clear) {
  if (full_clear) {
    sancov_state->pc_counter_set.ForEachNonZeroByte(
        [](size_t idx, uint8_t value) {}, 0,
        sancov_state->actual_pc_counter_set_size_aligned);
    if (sancov_state->flags.use_dataflow_features)
      sancov_state->data_flow_feature_set.ForEachNonZeroBit([](size_t idx) {});
    if (sancov_state->flags.use_cmp_features) {
      sancov_state->cmp_feature_set.ForEachNonZeroBit([](size_t idx) {});
      sancov_state->cmp_eq_set.ForEachNonZeroBit([](size_t idx) {});
      sancov_state->cmp_moddiff_set.ForEachNonZeroBit([](size_t idx) {});
      sancov_state->cmp_hamming_set.ForEachNonZeroBit([](size_t idx) {});
      sancov_state->cmp_difflog_set.ForEachNonZeroBit([](size_t idx) {});
    }
    if (sancov_state->flags.path_level != 0)
      sancov_state->path_feature_set.ForEachNonZeroBit([](size_t idx) {});
    if (sancov_state->flags.callstack_level != 0)
      sancov_state->callstack_set.ForEachNonZeroBit([](size_t idx) {});
    sancov_state->sancov_objects.ClearInlineCounters();

    for (auto* p = sancov_state->user_defined_begin;
         p != sancov_state->user_defined_end; ++p) {
      *p = 0;
    }
  }
}

// Adds a kPCs and/or k8bitCounters feature to `g_features` based on arguments.
// `idx` is a pc_index.
// `counter_value` (non-zero) is a counter value associated with that PC.
static void AddPcIndxedAndCounterToFeatures(
    size_t idx, uint8_t counter_value,
    const std::function<void(feature_t)> &feature_handler) {
  if (sancov_state->flags.use_pc_features) {
    feature_handler(feature_domains::kPCs.ConvertToMe(idx));
  }
  if (sancov_state->flags.use_counter_features) {
    feature_handler(feature_domains::k8bitCounters.ConvertToMe(
        Convert8bitCounterToNumber(idx, counter_value)));
  }
}

// Calls ExecutionMetadata::AppendCmpEntry for every CMP arg pair
// found in `cmp_trace`.
// Returns true if all appending succeeded.
// "noinline" so that we see it in a profile, if it becomes hot.
template <typename CmpTrace>
__attribute__((noinline)) void AppendCmpEntries(CmpTrace& cmp_trace,
                                                ExecutionMetadata& metadata) {
  cmp_trace.ForEachNonZero(
      [&](uint8_t size, const uint8_t* v0, const uint8_t* v1) {
        (void)metadata.AppendCmpEntry({v0, size}, {v1, size});
      });
}

void PostProcessSancov(bool reject_input) {
  sancov_state->g_features.clear();
  sancov_state->metadata.cmp_data.clear();

  if (sancov_state->flags.use_auto_dictionary && !reject_input) {
    sancov_state->ForEachTls([](ThreadLocalSancovState& tls) {
      AppendCmpEntries(tls.cmp_trace2, sancov_state->metadata);
      AppendCmpEntries(tls.cmp_trace4, sancov_state->metadata);
      AppendCmpEntries(tls.cmp_trace8, sancov_state->metadata);
      AppendCmpEntries(tls.cmp_traceN, sancov_state->metadata);
    });
  }

  std::function<void(feature_t)> feature_handler = MaybeAddFeature;
  if (reject_input) {
    // When suppressing a test, still iterate through all of the features as a
    // side effect of iteration is zeroing them out.  But don't write the
    // features anywhere.
    feature_handler = [](feature_t feature) {};
  }

  // Convert counters to features.
  sancov_state->pc_counter_set.ForEachNonZeroByte(
      [&feature_handler](size_t idx, uint8_t value) {
        AddPcIndxedAndCounterToFeatures(idx, value, feature_handler);
      },
      0, sancov_state->actual_pc_counter_set_size_aligned);

  // Convert data flow bit set to features.
  if (sancov_state->flags.use_dataflow_features) {
    sancov_state->data_flow_feature_set.ForEachNonZeroBit(
        [&feature_handler](size_t idx) {
          feature_handler(feature_domains::kDataFlow.ConvertToMe(idx));
        });
  }

  // Convert cmp bit set to features.
  if (sancov_state->flags.use_cmp_features) {
    // TODO(b/586537122): Remove cmp_feature_set.
    sancov_state->cmp_feature_set.ForEachNonZeroBit(
        [&feature_handler](size_t idx) {
          feature_handler(feature_domains::kCMP.ConvertToMe(idx));
        });
    sancov_state->cmp_eq_set.ForEachNonZeroBit([&feature_handler](size_t idx) {
      feature_handler(feature_domains::kCMPEq.ConvertToMe(idx));
    });
    sancov_state->cmp_moddiff_set.ForEachNonZeroBit(
        [&feature_handler](size_t idx) {
          feature_handler(feature_domains::kCMPModDiff.ConvertToMe(idx));
        });
    sancov_state->cmp_hamming_set.ForEachNonZeroBit(
        [&feature_handler](size_t idx) {
          feature_handler(feature_domains::kCMPHamming.ConvertToMe(idx));
        });
    sancov_state->cmp_difflog_set.ForEachNonZeroBit(
        [&feature_handler](size_t idx) {
          feature_handler(feature_domains::kCMPDiffLog.ConvertToMe(idx));
        });
  }

  // Convert path bit set to features.
  if (sancov_state->flags.path_level != 0) {
    sancov_state->path_feature_set.ForEachNonZeroBit(
        [&feature_handler](size_t idx) {
          feature_handler(feature_domains::kBoundedPath.ConvertToMe(idx));
        });
  }

  // Iterate all threads and get features from TLS data.
  sancov_state->ForEachTls([&feature_handler](ThreadLocalSancovState& tls) {
    SANCOV_CHECK(tls.top_frame_sp >= tls.lowest_sp,
                 "bad values of tls.top_frame_sp and tls.lowest_sp");
    uintptr_t lowest_sp = tls.lowest_sp;
    if (tls.sancov_lowest_sp != nullptr) {
      const uintptr_t sancov_lowest_sp = *tls.sancov_lowest_sp;
      if (sancov_lowest_sp <= tls.top_frame_sp &&
          sancov_lowest_sp <= lowest_sp &&
          sancov_lowest_sp >= tls.stack_region_low &&
          tls.stack_region_low > 0) {
        lowest_sp = sancov_lowest_sp;
      }
    }
    const size_t sp_diff = tls.top_frame_sp - lowest_sp;
    MaybeCheckStackLimit(sp_diff, /*is_current_stack=*/false);
    if (sancov_state->flags.callstack_level != 0) {
      feature_handler(feature_domains::kCallStack.ConvertToMe(sp_diff));
    }
  });

  if (sancov_state->flags.callstack_level != 0) {
    sancov_state->callstack_set.ForEachNonZeroBit(
        [&feature_handler](size_t idx) {
          feature_handler(feature_domains::kCallStack.ConvertToMe(idx));
        });
  }

  // Copy the features from __centipede_extra_features to g_features.
  // Zero features are ignored - we treat them as default (unset) values.
  for (auto* p = sancov_state->user_defined_begin;
       p != sancov_state->user_defined_end; ++p) {
    if (auto user_feature = *p) {
      // User domain ID is upper 32 bits
      feature_t user_domain_id = user_feature >> 32;
      // User feature ID is lower 32 bits.
      feature_t user_feature_id = user_feature & ((1ULL << 32) - 1);
      // There is no hard guarantee how many user domains are actually
      // available. If a user domain ID is out of range, alias it to an existing
      // domain. This is kinder than silently dropping the feature.
      user_domain_id %= std::size(feature_domains::kUserDomains);
      feature_handler(feature_domains::kUserDomains[user_domain_id].ConvertToMe(
          user_feature_id));
      *p = 0;  // cleanup for the next iteration.
    }
  }

  // Iterates all non-zero inline 8-bit counters, if they are present.
  // Calls AddPcIndxedAndCounterToFeatures on non-zero counters and zeroes them.
  if (sancov_state->flags.use_pc_features ||
      sancov_state->flags.use_counter_features) {
    sancov_state->sancov_objects.ForEachNonZeroInlineCounter(
        [&feature_handler](size_t idx, uint8_t counter_value) {
          AddPcIndxedAndCounterToFeatures(idx, counter_value, feature_handler);
        });
  }
}

const ExecutionMetadata& SanCovRuntimeGetExecutionMetadata() {
  return fuzztest::internal::sancov_state->metadata;
}

}  // namespace fuzztest::internal
