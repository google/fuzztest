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

#ifndef FUZZTEST_CENTIPEDE_SANCOV_INTERFACE_H_
#define FUZZTEST_CENTIPEDE_SANCOV_INTERFACE_H_

#include <cstdint>

#include "absl/base/nullability.h"
#include "./centipede/pc_info.h"

// NOTE: In addition to `always_inline`, also use `inline`, because some
// compilers require both to actually enforce inlining, e.g. GCC:
// https://gcc.gnu.org/onlinedocs/gcc/Common-Function-Attributes.html.
#define ENFORCE_INLINE __attribute__((always_inline)) inline

// Use this attribute for functions that must not be instrumented even if
// the runner is built with sanitizers (asan, etc).
#define NO_SANITIZE __attribute__((no_sanitize("all")))

NO_SANITIZE void __shared_sanitizer_cov_trace_const_cmp1(uint8_t Arg1,
                                                         uint8_t Arg2);
NO_SANITIZE void __shared_sanitizer_cov_trace_const_cmp2(uint16_t Arg1,
                                                         uint16_t Arg2);
NO_SANITIZE void __shared_sanitizer_cov_trace_const_cmp4(uint32_t Arg1,
                                                         uint32_t Arg2);
NO_SANITIZE void __shared_sanitizer_cov_trace_const_cmp8(uint64_t Arg1,
                                                         uint64_t Arg2);

NO_SANITIZE void __shared_sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2);
NO_SANITIZE void __shared_sanitizer_cov_trace_cmp2(uint16_t Arg1,
                                                   uint16_t Arg2);
NO_SANITIZE void __shared_sanitizer_cov_trace_cmp4(uint32_t Arg1,
                                                   uint32_t Arg2);
NO_SANITIZE void __shared_sanitizer_cov_trace_cmp8(uint64_t Arg1,
                                                   uint64_t Arg2);

#ifdef __cplusplus
extern "C" {
#endif

NO_SANITIZE void __framework_sanitizer_cov_load1(uint8_t *addr);
NO_SANITIZE void __framework_sanitizer_cov_load2(uint16_t *addr);
NO_SANITIZE void __framework_sanitizer_cov_load4(uint32_t *addr);
NO_SANITIZE void __framework_sanitizer_cov_load8(uint64_t *addr);
NO_SANITIZE void __framework_sanitizer_cov_load16(__uint128_t *addr);

NO_SANITIZE void __framework_sanitizer_cov_trace_const_cmp2(uint16_t Arg1,
                                                            uint16_t Arg2);
NO_SANITIZE void __framework_sanitizer_cov_trace_const_cmp4(uint32_t Arg1,
                                                            uint32_t Arg2);
NO_SANITIZE void __framework_sanitizer_cov_trace_const_cmp8(uint64_t Arg1,
                                                            uint64_t Arg2);

NO_SANITIZE void __framework_sanitizer_cov_trace_cmp2(uint16_t Arg1,
                                                      uint16_t Arg2);
NO_SANITIZE void __framework_sanitizer_cov_trace_cmp4(uint32_t Arg1,
                                                      uint32_t Arg2);
NO_SANITIZE void __framework_sanitizer_cov_trace_cmp8(uint64_t Arg1,
                                                      uint64_t Arg2);

void __framework_sanitizer_cov_8bit_counters_init(uint8_t *beg, uint8_t *end);

void __framework_sanitizer_cov_pcs_init(
    const fuzztest::internal::PCInfo *absl_nonnull beg,
    const fuzztest::internal::PCInfo *end);

void __framework_sanitizer_cov_cfs_init(const uintptr_t *beg,
                                        const uintptr_t *end);

void __framework_sanitizer_cov_trace_pc_guard_init(
    fuzztest::internal::PCGuard *absl_nonnull start,
    fuzztest::internal::PCGuard *stop);

NO_SANITIZE void __framework_sanitizer_cov_trace_pc_guard(
    fuzztest::internal::PCGuard *absl_nonnull guard);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // FUZZTEST_CENTIPEDE_SANCOV_INTERFACE_H_
