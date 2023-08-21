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

// Instrumentation callbacks for SanitizerCoverage (sancov).
// https://clang.llvm.org/docs/SanitizerCoverage.html

#include "./centipede/runner_sancov_object.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "./centipede/pc_info.h"
#include "./centipede/runner_dl_info.h"
#include "./centipede/runner_utils.h"

namespace centipede {

void SanCovObjectArray::PCGuardInit(PCGuard *start, PCGuard *stop) {
  // Ignore repeated calls with the same arguments.
  if (size_ != 0 && objects_[size_ - 1].pc_guard_start == start) return;
  RunnerCheck(size_ < kMaxSize, "too many sancov objects");
  auto &sancov_object = objects_[size_++];
  sancov_object.pc_guard_start = start;
  sancov_object.pc_guard_stop = stop;
}

void SanCovObjectArray::Inline8BitCountersInit(
    uint8_t *inline_8bit_counters_start, uint8_t *inline_8bit_counters_stop) {
  // Ignore repeated calls with the same arguments.
  if (size_ != 0 && objects_[size_ - 1].inline_8bit_counters_start ==
                        inline_8bit_counters_start) {
    return;
  }
  RunnerCheck(size_ < kMaxSize, "too many sancov objects");
  auto &sancov_object = objects_[size_++];
  sancov_object.inline_8bit_counters_start = inline_8bit_counters_start;
  sancov_object.inline_8bit_counters_stop = inline_8bit_counters_stop;
}

void SanCovObjectArray::PCInfoInit(const PCInfo *pcs_beg,
                                   const PCInfo *pcs_end) {
  const char *called_early =
      "__sanitizer_cov_pcs_init is called before either of "
      "__sanitizer_cov_trace_pc_guard_init or "
      "__sanitizer_cov_8bit_counters_init";
  RunnerCheck(size_ != 0, called_early);
  // Assumes either __sanitizer_cov_trace_pc_guard_init or
  // sanitizer_cov_8bit_counters_init was already called on this object.
  auto &sancov_object = objects_[size_ - 1];
  const size_t guard_size =
      sancov_object.pc_guard_stop - sancov_object.pc_guard_start;
  const size_t counter_size = sancov_object.inline_8bit_counters_stop -
                              sancov_object.inline_8bit_counters_start;
  RunnerCheck(guard_size != 0 || counter_size != 0, called_early);
  RunnerCheck(std::max(guard_size, counter_size) == pcs_end - pcs_beg,
              "__sanitizer_cov_pcs_init: mismatch between guard/counter size"
              " and pc table size");
  sancov_object.pcs_beg = pcs_beg;
  sancov_object.pcs_end = pcs_end;
  sancov_object.dl_info = GetDlInfo(pcs_beg->pc);
  RunnerCheck(sancov_object.dl_info.IsSet(), "failed to compute dl_info");
}

void SanCovObjectArray::CFSInit(const uintptr_t *cfs_beg,
                                const uintptr_t *cfs_end) {
  // Assumes __sanitizer_cov_pcs_init has been called.
  const char *called_early =
      "__sanitizer_cov_cfs_init is called before __sanitizer_cov_pcs_init";
  RunnerCheck(size_ != 0, called_early);
  auto &sancov_object = objects_[size_ - 1];
  RunnerCheck(sancov_object.pcs_beg != nullptr, called_early);
  sancov_object.cfs_beg = cfs_beg;
  sancov_object.cfs_end = cfs_end;
}

std::vector<PCInfo> SanCovObjectArray::CreatePCTable() const {
  // Compute the total number of PCs in all objects.
  size_t num_pcs = 0;
  for (const auto &object : objects_) {
    num_pcs += object.pcs_end - object.pcs_beg;
  }
  // Populate the result.
  std::vector<PCInfo> result(num_pcs);
  size_t idx = 0;
  for (const auto &object : objects_) {
    for (const auto *pc_info = object.pcs_beg; pc_info != object.pcs_end;
         ++pc_info) {
      result[idx] = *pc_info;
      // Subtract the ASRL base.
      result[idx].pc -= object.dl_info.start_address;
      ++idx;
    }
  }
  RunnerCheck(idx == num_pcs, "error while computing pc table");
  return result;
}

}  // namespace centipede
