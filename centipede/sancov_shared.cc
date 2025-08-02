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

#include "./centipede/feature.h"
#include "./centipede/int_utils.h"
#include "./centipede/sancov_interface.h"
#include "./centipede/shared_coverage_state.h"

using fuzztest::internal::shared_coverage_state;
using fuzztest::internal::tls;

// NOTE: Enforce inlining so that `__builtin_return_address` works.
ENFORCE_INLINE static void TraceCmp(uint64_t Arg1, uint64_t Arg2) {
  if (!shared_coverage_state.run_time_flags.use_cmp_features) return;
  auto caller_pc = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  auto pc_offset = caller_pc - shared_coverage_state.main_object.start_address;
  uintptr_t hash =
      fuzztest::internal::Hash64Bits(pc_offset) ^ tls.path_ring_buffer.hash();
  if (Arg1 == Arg2) {
    shared_coverage_state.cmp_eq_set.set(hash);
  } else {
    hash <<= 6;  // ABTo* generate 6-bit numbers.
    shared_coverage_state.cmp_moddiff_set.set(
        hash | fuzztest::internal::ABToCmpModDiff(Arg1, Arg2));
    shared_coverage_state.cmp_hamming_set.set(
        hash | fuzztest::internal::ABToCmpHamming(Arg1, Arg2));
    shared_coverage_state.cmp_difflog_set.set(
        hash | fuzztest::internal::ABToCmpDiffLog(Arg1, Arg2));
  }
}

void __shared_sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2) {
  TraceCmp(Arg1, Arg2);
}

void __shared_sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2) {
  TraceCmp(Arg1, Arg2);
}

void __shared_sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2) {
  TraceCmp(Arg1, Arg2);
}

void __shared_sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2) {
  TraceCmp(Arg1, Arg2);
}

void __shared_sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2) {
  TraceCmp(Arg1, Arg2);
}

void __shared_sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2) {
  TraceCmp(Arg1, Arg2);
}

void __shared_sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2) {
  TraceCmp(Arg1, Arg2);
}

void __shared_sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2) {
  TraceCmp(Arg1, Arg2);
}
