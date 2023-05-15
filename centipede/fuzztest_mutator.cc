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

#include "./centipede/fuzztest_mutator.h"

namespace centipede {

FuzzTestMutator::FuzzTestMutator(uintptr_t seed)
    : prng_(std::seed_seq({seed})),
      domain_(
          fuzztest::internal::ContainerOfImpl<std::vector<uint8_t>,
                                              ArbitraryByte>(ArbitraryByte())
              .WithMinSize(1)) {
  if (fuzztest::internal::GetExecutionCoverage() == nullptr) {
    auto* execution_coverage = new fuzztest::internal::ExecutionCoverage({});
    fuzztest::internal::SetExecutionCoverage(execution_coverage);
    execution_coverage->SetIsTracing(true);
  }
}

void FuzzTestMutator::MutateMany(const std::vector<ByteArray>& inputs,
                                 size_t num_mutants,
                                 std::vector<ByteArray>& mutants) {
  mutants.clear();
  mutants.reserve(num_mutants);
  for (int i = 0; i < num_mutants; ++i) {
    auto mutant = inputs[absl::Uniform<size_t>(prng_, 0, inputs.size())];
    domain_.Mutate(mutant, prng_, /*only_shrink=*/false);
    mutants.push_back(mutant);
  }
}

bool FuzzTestMutator::SetCmpDictionary(ByteSpan cmp_data) {
  for (size_t i = 0; i < cmp_data.size();) {
    auto size = cmp_data[i];
    if (size < kMinCmpEntrySize) return false;
    if (size > kMaxCmpEntrySize) return false;
    if (i + 2 * size + 1 > cmp_data.size()) return false;
    const uint8_t* a = cmp_data.begin() + i + 1;
    const uint8_t* b = cmp_data.begin() + i + size + 1;
    static_assert(kMinCmpEntrySize > 1);
    if (size == 2) {
      fuzztest::internal::GetExecutionCoverage()
          ->GetTablesOfRecentCompares()
          .GetMutable<2>()
          .Insert(*(const uint16_t*)a, *(const uint16_t*)b);
    } else if (size == 4) {
      fuzztest::internal::GetExecutionCoverage()
          ->GetTablesOfRecentCompares()
          .GetMutable<4>()
          .Insert(*(const uint32_t*)a, *(const uint32_t*)b);
    } else if (size == 8) {
      fuzztest::internal::GetExecutionCoverage()
          ->GetTablesOfRecentCompares()
          .GetMutable<8>()
          .Insert(*(const uint64_t*)a, *(const uint64_t*)b);
    } else {
      fuzztest::internal::GetExecutionCoverage()
          ->GetTablesOfRecentCompares()
          .GetMutable<0>()
          .Insert(a, b, size);
    }
    i += 1 + 2 * size;
  }
  return true;
}

void FuzzTestMutator::AddToDictionary(
    const std::vector<ByteArray>& dict_entries) {
  domain_.WithDictionary(dict_entries);
}

}  // namespace centipede
