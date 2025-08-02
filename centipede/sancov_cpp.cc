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

#include <cstdint>
#include <cstdio>

#include "absl/base/nullability.h"
#include "./centipede/feature.h"
#include "./centipede/pc_info.h"
#include "./centipede/runner.h"
#include "./centipede/runner_dl_info.h"
#include "./centipede/sancov_interface.h"
#include "./centipede/shared_coverage_state.h"

using fuzztest::internal::PCGuard;
using fuzztest::internal::PCInfo;
using fuzztest::internal::shared_coverage_state;
using fuzztest::internal::state;
using fuzztest::internal::tls;

// NOTE: Enforce inlining so that `__builtin_return_address` works.
ENFORCE_INLINE static void TraceLoad(void *addr) {
  if (!shared_coverage_state.run_time_flags.use_dataflow_features) return;
  auto caller_pc = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  auto load_addr = reinterpret_cast<uintptr_t>(addr);
  auto pc_offset = caller_pc - shared_coverage_state.main_object.start_address;
  if (pc_offset >= shared_coverage_state.main_object.size)
    return;  // PC outside main obj.
  auto addr_offset =
      load_addr - shared_coverage_state.main_object.start_address;
  if (addr_offset >= shared_coverage_state.main_object.size)
    return;  // Not a global address.
  state.data_flow_feature_set.set(fuzztest::internal::ConvertPcPairToNumber(
      pc_offset, addr_offset, shared_coverage_state.main_object.size));
}

void __framework_sanitizer_cov_load1(uint8_t *addr) { TraceLoad(addr); }

void __framework_sanitizer_cov_load2(uint16_t *addr) { TraceLoad(addr); }

void __framework_sanitizer_cov_load4(uint32_t *addr) { TraceLoad(addr); }

void __framework_sanitizer_cov_load8(uint64_t *addr) { TraceLoad(addr); }

void __framework_sanitizer_cov_load16(__uint128_t *addr) { TraceLoad(addr); }

void __framework_sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2) {
  if (Arg1 != Arg2 && shared_coverage_state.run_time_flags.use_auto_dictionary)
    tls.cmp_trace2.Capture(Arg1, Arg2);
}

void __framework_sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2) {
  if (Arg1 != Arg2 && shared_coverage_state.run_time_flags.use_auto_dictionary)
    tls.cmp_trace4.Capture(Arg1, Arg2);
}

void __framework_sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2) {
  if (Arg1 != Arg2 && shared_coverage_state.run_time_flags.use_auto_dictionary)
    tls.cmp_trace8.Capture(Arg1, Arg2);
}

void __framework_sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2) {
  if (Arg1 != Arg2 && shared_coverage_state.run_time_flags.use_auto_dictionary)
    tls.cmp_trace2.Capture(Arg1, Arg2);
}

void __framework_sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2) {
  if (Arg1 != Arg2 && shared_coverage_state.run_time_flags.use_auto_dictionary)
    tls.cmp_trace4.Capture(Arg1, Arg2);
}

void __framework_sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2) {
  if (Arg1 != Arg2 && shared_coverage_state.run_time_flags.use_auto_dictionary)
    tls.cmp_trace8.Capture(Arg1, Arg2);
}

void __framework_sanitizer_cov_8bit_counters_init(uint8_t *beg, uint8_t *end) {
  state.sancov_objects.Inline8BitCountersInit(beg, end);
}

void __framework_sanitizer_cov_pcs_init(const PCInfo *absl_nonnull beg,
                                        const PCInfo *end) {
  state.sancov_objects.PCInfoInit(beg, end);
}

void __framework_sanitizer_cov_cfs_init(const uintptr_t *beg,
                                        const uintptr_t *end) {
  state.sancov_objects.CFSInit(beg, end);
}

// Updates the state of the paths, `path_level > 0`.
// Marked noinline so that not to create spills/fills on the fast path
// of __sanitizer_cov_trace_pc_guard.
__attribute__((noinline)) static void HandlePath(uintptr_t normalized_pc) {
  uintptr_t hash = tls.path_ring_buffer.push(normalized_pc);
  state.path_feature_set.set(hash);
}

// Handles one observed PC.
// `normalized_pc` is an integer representation of PC that is stable between
// the executions.
// `is_function_entry` is true if the PC is known to be a function entry.
// With __sanitizer_cov_trace_pc_guard this is an index of PC in the PC table.
// With __sanitizer_cov_trace_pc this is PC itself, normalized by subtracting
// the DSO's dynamic start address.
static ENFORCE_INLINE void HandleOnePc(PCGuard pc_guard) {
  if (!shared_coverage_state.run_time_flags.use_pc_features) return;
  state.pc_counter_set.SaturatedIncrement(pc_guard.pc_index);

  if (pc_guard.is_function_entry) {
    uintptr_t sp = reinterpret_cast<uintptr_t>(__builtin_frame_address(0));
    // It should be rare for the stack depth to exceed the previous record.
    if (__builtin_expect(
            sp < tls.lowest_sp &&
                // And ignore the stack pointer when it is not in the known
                // region (e.g. for signal handling with an alternative stack).
                (tls.stack_region_low == 0 || sp >= tls.stack_region_low),
            0)) {
      tls.lowest_sp = sp;
      fuzztest::internal::CheckStackLimit(sp);
    }
    if (shared_coverage_state.run_time_flags.callstack_level != 0) {
      tls.call_stack.OnFunctionEntry(pc_guard.pc_index, sp);
      state.callstack_set.set(tls.call_stack.Hash());
    }
  }

  // path features.
  if (shared_coverage_state.run_time_flags.path_level != 0)
    HandlePath(pc_guard.pc_index);
}

// Sets `actual_pc_counter_set_size_aligned` to `size`, properly aligned up.
static void UpdatePcCounterSetSizeAligned(size_t size) {
  constexpr size_t kAlignment = state.pc_counter_set.kSizeMultiple;
  constexpr size_t kMask = kAlignment - 1;
  state.actual_pc_counter_set_size_aligned = (size + kMask) & ~kMask;
}

void __framework_sanitizer_cov_trace_pc_guard_init(PCGuard *absl_nonnull start,
                                                   PCGuard *stop) {
  state.sancov_objects.PCGuardInit(start, stop);
  UpdatePcCounterSetSizeAligned(state.sancov_objects.NumInstrumentedPCs());
}

void __framework_sanitizer_cov_trace_pc_guard(PCGuard *absl_nonnull guard) {
  // This function may be called very early during the DSO initialization,
  // before the values of `*guard` are initialized to non-zero.
  // But it will immidiately return because state.run_time_flags.use_pc_features
  // is false. Once state.run_time_flags.use_pc_features becomes true, it is
  // already ok to call this function.
  HandleOnePc(*guard);
}

// Caller PC is the PC of the call instruction.
// Return address is the PC where the callee will return upon completion.
// On x86_64, CallerPC == ReturnAddress - 5
// On AArch64, CallerPC == ReturnAddress - 4
static uintptr_t ReturnAddressToCallerPc(uintptr_t return_address) {
#ifdef __x86_64__
  return return_address - 5;
#elif defined(__aarch64__)
  return return_address - 4;
#else
#error "unsupported architecture"
#endif
}

// MainObjectLazyInit() and helpers allow us to initialize state.main_object
// lazily and thread-safely on the first call to __sanitizer_cov_trace_pc().
//
// TODO(kcc): consider removing :dl_path_suffix= since with lazy init
// we can auto-detect the instrumented DSO.
//
// TODO(kcc): this lazy init is brittle.
// It assumes that __sanitizer_cov_trace_pc is the only code that touches
// state.main_object concurrently. I.e. we can not blindly reuse this lazy init
// for other instrumentation callbacks that use state.main_object.
// This code is also considered *temporary* because
// a) __sanitizer_cov_trace_pc is obsolete and we hope to not need it in future.
// b) a better option might be to do a non-lazy init by intercepting dlopen.
//
// We do not call MainObjectLazyInit() in
// __sanitizer_cov_trace_pc_guard() because
// a) there is not use case for that currently and
// b) it will slowdown the hot function.
static pthread_once_t main_object_lazy_init_once = PTHREAD_ONCE_INIT;
static void MainObjectLazyInitOnceCallback() {
  shared_coverage_state.main_object = fuzztest::internal::GetDlInfo(
      shared_coverage_state.GetStringFlag(":dl_path_suffix="));
  fprintf(stderr, "MainObjectLazyInitOnceCallback %zx\n",
          shared_coverage_state.main_object.start_address);
  UpdatePcCounterSetSizeAligned(state.reverse_pc_table.NumPcs());
}

__attribute__((noinline)) static void MainObjectLazyInit() {
  pthread_once(&main_object_lazy_init_once, MainObjectLazyInitOnceCallback);
}

// TODO(kcc): [impl] add proper testing for this callback.
// TODO(kcc): make sure the pc_table in the engine understands the raw PCs.
// TODO(kcc): this implementation is temporary. In order for symbolization to
// work we will need to translate the PC into a PCIndex or make pc_table sparse.
// See https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-pcs.
// This instrumentation is redundant if other instrumentation
// (e.g. trace-pc-guard) is available, but GCC as of 2022-04 only supports
// this variant.
extern "C" void __sanitizer_cov_trace_pc() {
  uintptr_t pc = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  if (!shared_coverage_state.main_object.start_address ||
      !state.actual_pc_counter_set_size_aligned) {
    // Don't track coverage at all before the PC table is initialized.
    if (state.reverse_pc_table.NumPcs() == 0) return;
    MainObjectLazyInit();
  }
  pc -= shared_coverage_state.main_object.start_address;
  pc = ReturnAddressToCallerPc(pc);
  const auto pc_guard = state.reverse_pc_table.GetPCGuard(pc);
  // TODO(kcc): compute is_function_entry for this case.
  if (pc_guard.IsValid()) HandleOnePc(pc_guard);
}
