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

#ifndef THIRD_PARTY_CENTIPEDE_REVERSE_PC_TABLE_H_
#define THIRD_PARTY_CENTIPEDE_REVERSE_PC_TABLE_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "./centipede/pc_info.h"

namespace centipede {

// Maps PCs to indices.
class ReversePCTable {
 public:
  static constexpr size_t kUnknownPC = -1;

  // Constructs the reverse PC table from `pc_table`.
  // The assumption is that all PCs are relatively small, such that the
  // implementation is allowed to create an array of max_element(pcs) elements.
  // TODO(kcc): make use of PCInfo::flags.
  void SetFromPCs(const PCTable& pc_table) {
    num_pcs_ = pc_table.size();
    if (table_ != nullptr) delete[] table_;
    if (num_pcs_ == 0) {
      size_ = 0;
      table_ = nullptr;
      return;
    }
    // Compute max_pc.
    uintptr_t max_pc = 0;
    for (const auto& pc_info : pc_table) {
      max_pc = std::max(max_pc, pc_info.pc);
    }
    // Create an array of max_pc + 1 elements such that we can directly
    // index this array with any pc from `pcs`.
    size_ = max_pc + 1;
    table_ = new size_t[size_];
    std::fill(table_, table_ + size_, kUnknownPC);
    for (size_t idx = 0; idx < pc_table.size(); ++idx) {
      table_[pc_table[idx].pc] = idx;
    }
  }

  // Returns the index of `pc` inside the `pcs` (passed to SetFromPCs()).
  // If `pc` was not present in `pcs`, returns kUnknownPC.
  // This is a hot function and needs to be as simple and fast as possible.
  size_t GetPCIndex(uintptr_t pc) const {
    if (pc >= size_) return kUnknownPC;
    return table_[pc];
  }

  // Returns the number of PCs that was passes to SetFromPCs().
  size_t NumPcs() const { return num_pcs_; }

 private:
  // We use size_ and table_ pointer instead of std::vector<> because
  // (1) we need ReversePCTable object to be accessible even after the
  // destruction (in static storage duration); (2) size_ is cheaper to
  // compute inside GetPCIndex(). This would cause leakage if not
  // declared as static - one can explicitly call SetFromPCs({}) to
  // free the table.
  size_t size_ = 0;
  size_t num_pcs_ = 0;
  size_t* table_ = nullptr;
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_REVERSE_PC_TABLE_H_
