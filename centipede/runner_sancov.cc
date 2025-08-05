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

// Instrumentation callbacks for SanitizerCoverage (sancov).
// https://clang.llvm.org/docs/SanitizerCoverage.html

#include <pthread.h>

#include <cstdint>

#include "absl/base/nullability.h"
#include "./centipede/pc_info.h"
#include "./centipede/sancov_interface.h"

namespace fuzztest::internal {
void RunnerSancov() {}  // to be referenced in runner.cc
}  // namespace fuzztest::internal

using fuzztest::internal::PCGuard;
using fuzztest::internal::PCInfo;

// Tracing data flow.
// The instrumentation is provided by
// https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-data-flow.
// For every load we get the address of the load. We can also get the caller PC.
// If the load address in
// [main_object.start_address, main_object.start_address + main_object.size),
// it is likely a global.
// We form a feature from a pair of {caller_pc, address_of_load}.
// The rationale here is that loading from a global address unique for the
// given PC is an interesting enough behavior that it warrants its own feature.
//
// Downsides:
// * The instrumentation is expensive, it can easily add 2x slowdown.
// * This creates plenty of features, easily 10x compared to control flow,
//   and bloats the corpus. But this is also what we want to achieve here.

//------------------------------------------------------------------------------
// Implementations of the external sanitizer coverage hooks.
//------------------------------------------------------------------------------

extern "C" {
NO_SANITIZE void __sanitizer_cov_load1(uint8_t *addr) {
  __framework_sanitizer_cov_load1(addr);
}
NO_SANITIZE void __sanitizer_cov_load2(uint16_t *addr) {
  __framework_sanitizer_cov_load2(addr);
}
NO_SANITIZE void __sanitizer_cov_load4(uint32_t *addr) {
  __framework_sanitizer_cov_load4(addr);
}
NO_SANITIZE void __sanitizer_cov_load8(uint64_t *addr) {
  __framework_sanitizer_cov_load8(addr);
}
NO_SANITIZE void __sanitizer_cov_load16(__uint128_t *addr) {
  __framework_sanitizer_cov_load16(addr);
}

NO_SANITIZE
void __sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2) {
  __shared_sanitizer_cov_trace_const_cmp1(Arg1, Arg2);
}
NO_SANITIZE
void __sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2) {
  __shared_sanitizer_cov_trace_const_cmp2(Arg1, Arg2);
  __framework_sanitizer_cov_trace_const_cmp2(Arg1, Arg2);
}
NO_SANITIZE
void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2) {
  __shared_sanitizer_cov_trace_const_cmp4(Arg1, Arg2);
  __framework_sanitizer_cov_trace_const_cmp4(Arg1, Arg2);
}
NO_SANITIZE
void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2) {
  __shared_sanitizer_cov_trace_const_cmp8(Arg1, Arg2);
  __framework_sanitizer_cov_trace_const_cmp8(Arg1, Arg2);
}
NO_SANITIZE
void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2) {
  __shared_sanitizer_cov_trace_cmp1(Arg1, Arg2);
}
NO_SANITIZE
void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2) {
  __shared_sanitizer_cov_trace_cmp2(Arg1, Arg2);
  __framework_sanitizer_cov_trace_cmp2(Arg1, Arg2);
}
NO_SANITIZE
void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2) {
  __shared_sanitizer_cov_trace_cmp4(Arg1, Arg2);
  __framework_sanitizer_cov_trace_cmp4(Arg1, Arg2);
}
NO_SANITIZE
void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2) {
  __shared_sanitizer_cov_trace_cmp8(Arg1, Arg2);
  __framework_sanitizer_cov_trace_cmp8(Arg1, Arg2);
}
// TODO(kcc): [impl] handle switch.
NO_SANITIZE
void __sanitizer_cov_trace_switch(uint64_t Val, uint64_t *Cases) {}

// This function is called at startup when
// -fsanitize-coverage=inline-8bit-counters is used.
// See https://clang.llvm.org/docs/SanitizerCoverage.html#inline-8bit-counters
void __sanitizer_cov_8bit_counters_init(uint8_t *beg, uint8_t *end) {
  __framework_sanitizer_cov_8bit_counters_init(beg, end);
}

// https://clang.llvm.org/docs/SanitizerCoverage.html#pc-table
// This function is called at the DSO init time, potentially several times.
// When called from the same DSO, the arguments will always be the same.
// If a different DSO calls this function, it will have different arguments.
// We currently do not support more than one sancov-instrumented DSO.
void __sanitizer_cov_pcs_init(const PCInfo *absl_nonnull beg,
                              const PCInfo *end) {
  __framework_sanitizer_cov_pcs_init(beg, end);
}

// https://clang.llvm.org/docs/SanitizerCoverage.html#tracing-control-flow
// This function is called at the DSO init time.
void __sanitizer_cov_cfs_init(const uintptr_t *beg, const uintptr_t *end) {
  __framework_sanitizer_cov_cfs_init(beg, end);
}

// This function is called at the DSO init time.
void __sanitizer_cov_trace_pc_guard_init(PCGuard *absl_nonnull start,
                                         PCGuard *stop) {
  __framework_sanitizer_cov_trace_pc_guard_init(start, stop);
}

// This function is called on every instrumented edge.
NO_SANITIZE
void __sanitizer_cov_trace_pc_guard(PCGuard *absl_nonnull guard) {
  __framework_sanitizer_cov_trace_pc_guard(guard);
}

}  // extern "C"
