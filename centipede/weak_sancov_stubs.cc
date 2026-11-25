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

#define WEAK_SANCOV_DEF(return_type, name, ...)     \
  extern "C" __attribute__((visibility("default"))) \
  __attribute__((weak)) return_type                 \
  name(__VA_ARGS__)

WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_cmp, void) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_cmp1, uint8_t, uint8_t) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_cmp2, uint16_t, uint16_t) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_cmp4, uint32_t, uint32_t) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_cmp8, uint64_t, uint64_t) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_const_cmp1, uint8_t, uint8_t) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_const_cmp2, uint16_t, uint16_t) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_const_cmp4, uint32_t, uint32_t) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_const_cmp8, uint64_t, uint64_t) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_switch, uint64_t, uint64_t*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_div4, uint32_t) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_div8, uint64_t) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_gep, uintptr_t) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_pc_indir, uintptr_t) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_8bit_counters_init, uint8_t*, uint8_t*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_bool_flag_init, bool*, bool*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_pcs_init, const uintptr_t*,
                const uintptr_t*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_cfs_init, const uintptr_t*,
                const uintptr_t*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_pc, void) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_pc_entry, void) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_pc_exit, void) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_pc_guard, uint32_t*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_trace_pc_guard_init, uint32_t*,
                uint32_t*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_load1, uint8_t*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_load2, uint16_t*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_load4, uint32_t*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_load8, uint64_t*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_load16, void*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_store1, uint8_t*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_store2, uint16_t*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_store4, uint32_t*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_store8, uint64_t*) {}
WEAK_SANCOV_DEF(void, __sanitizer_cov_store16, void*) {}

WEAK_SANCOV_DEF(void, __sanitizer_cov_stack_depth, void) {}
#if !defined(_WIN32)
extern "C" {
__attribute__((visibility("default")))
__attribute__((weak)) thread_local uintptr_t __sancov_lowest_stack;
}
#endif
