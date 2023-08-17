// Copyright 2023 The Centipede Authors.
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

#ifndef THIRD_PARTY_CENTIPEDE_RUNNER_SANCOV_OBJECT_H_
#define THIRD_PARTY_CENTIPEDE_RUNNER_SANCOV_OBJECT_H_

#include <cstddef>
#include <cstdint>

#include "./centipede/pc_info.h"

// TODO(kcc): gradually replace the old code in runner_sancov.cc with this code.
// The difference is that the old code allows only one sancov-instrumented DSO,
// while this code allows multiple instrumented DSO.
// TODO(kcc): this code is not a full replacement for the old code yet.

namespace centipede {

// Information about one sancov-instrumented object (DSO).
// See https://clang.llvm.org/docs/SanitizerCoverage.html.
// These structs are created as globals and are linker-initialized to zero.
struct SanCovObject {
  PCGuard *pc_guard_start;              // __sanitizer_cov_trace_pc_guard_init.
  PCGuard *pc_guard_stop;               // __sanitizer_cov_trace_pc_guard_init.
  const PCInfo *pcs_beg;                // __sanitizer_cov_pcs_init
  const PCInfo *pcs_end;                // __sanitizer_cov_pcs_init
  const uintptr_t *cfs_beg;             // __sanitizer_cov_cfs_init
  const uintptr_t *cfs_end;             // __sanitizer_cov_cfs_init
  uint8_t *inline_8bit_counters_start;  // __sanitizer_cov_8bit_counters_init
  uint8_t *inline_8bit_counters_stop;   // __sanitizer_cov_8bit_counters_init
};

// A fixed size array of SanCovObject structs.
// Also linker-initialized to zero.
class SanCovObjectArray {
 public:
  // To be called in __sanitizer_cov_trace_pc_guard_init.
  void PCGuardInit(PCGuard *start, PCGuard *stop);

  // To be called in __sanitizer_cov_pcs_init.
  void PCInfoInit(const PCInfo *pcs_beg, const PCInfo *pcs_end);

  // To be called in __sanitizer_cov_cfs_init.
  void CFSInit(const uintptr_t *cfs_beg, const uintptr_t *cfs_end);

  // To be called in __sanitizer_cov_8bit_counters_init.
  void Inline8BitCountersInit(uint8_t *inline_8bit_counters_start,
                              uint8_t *inline_8bit_counters_stop);

  // Returns the number of sancov-instrumented objects observed so far.
  size_t size() const { return size_; }

 private:
  static constexpr size_t kMaxSize = 1024;
  size_t size_;
  SanCovObject objects_[kMaxSize];
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_RUNNER_SANCOV_OBJECT_H_
