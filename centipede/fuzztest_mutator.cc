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

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <random>

#include "absl/random/random.h"
#include "./centipede/byte_array_mutator.h"
#include "./centipede/defs.h"
#include "./centipede/knobs.h"
#include "./fuzztest/domain_core.h"

namespace centipede {

namespace {

using MutatorDomainBase =
    decltype(fuzztest::VectorOf(fuzztest::Arbitrary<uint8_t>()));

}  // namespace

class FuzzTestMutator::MutatorDomain : public MutatorDomainBase {
 public:
  MutatorDomain()
      : MutatorDomainBase(fuzztest::VectorOf(fuzztest::Arbitrary<uint8_t>())) {}
};

FuzzTestMutator::FuzzTestMutator(const Knobs &knobs, uint64_t seed)
    : knobs_(knobs),
      prng_(std::seed_seq({seed, seed >> 32})),
      domain_(std::make_unique<MutatorDomain>()) {
  domain_->WithMinSize(1).WithMaxSize(max_len_);
  if (fuzztest::internal::GetExecutionCoverage() == nullptr) {
    auto* execution_coverage = new fuzztest::internal::ExecutionCoverage({});
    execution_coverage->SetIsTracing(true);
    fuzztest::internal::SetExecutionCoverage(execution_coverage);
  }
}

FuzzTestMutator::~FuzzTestMutator() = default;

void FuzzTestMutator::CrossOverInsert(ByteArray &data, const ByteArray &other) {
  // insert other[first:first+size] at data[pos]
  const auto size = absl::Uniform<size_t>(
      prng_, 1, std::min(max_len_ - data.size(), other.size()) + 1);
  const auto first = absl::Uniform<size_t>(prng_, 0, other.size() - size + 1);
  const auto pos = absl::Uniform<size_t>(prng_, 0, data.size() + 1);
  data.insert(data.begin() + pos, other.begin() + first,
              other.begin() + first + size);
}

void FuzzTestMutator::CrossOverOverwrite(ByteArray &data,
                                         const ByteArray &other) {
  // Overwrite data[pos:pos+size] with other[first:first+size].
  // Overwrite no more than half of data.
  size_t max_size = std::max(1UL, data.size() / 2);
  const auto first = absl::Uniform<size_t>(prng_, 0, other.size());
  max_size = std::min(max_size, other.size() - first);
  const auto size = absl::Uniform<size_t>(prng_, 1, max_size + 1);
  const auto pos = absl::Uniform<size_t>(prng_, 0, data.size() - size + 1);
  std::copy(other.begin() + first, other.begin() + first + size,
            data.begin() + pos);
}

void FuzzTestMutator::CrossOver(ByteArray &data, const ByteArray &other) {
  if (data.size() >= max_len_) {
    CrossOverOverwrite(data, other);
  } else {
    if (knobs_.GenerateBool(knob_cross_over_insert_or_overwrite, prng_())) {
      CrossOverInsert(data, other);
    } else {
      CrossOverOverwrite(data, other);
    }
  }
}

void FuzzTestMutator::MutateMany(const std::vector<MutationInputRef>& inputs,
                                 size_t num_mutants,
                                 std::vector<ByteArray>& mutants) {
  if (inputs.empty()) abort();
  // TODO(xinhaoyuan): Consider metadata in other inputs instead of always the
  // first one.
  SetMetadata(inputs[0].metadata != nullptr ? *inputs[0].metadata
                                            : ExecutionMetadata());
  mutants.clear();
  mutants.reserve(num_mutants);
  for (int i = 0; i < num_mutants; ++i) {
    auto mutant = inputs[absl::Uniform<size_t>(prng_, 0, inputs.size())].data;
    if (mutant.size() > max_len_) mutant.resize(max_len_);
    if (knobs_.GenerateBool(knob_mutate_or_crossover, prng_())) {
      // Perform crossover with some other input. It may be the same input.
      const auto &other_input =
          inputs[absl::Uniform<size_t>(prng_, 0, inputs.size())].data;
      CrossOver(mutant, other_input);
    } else {
      domain_->Mutate(mutant, prng_, /*only_shrink=*/false);
    }
    mutants.push_back(std::move(mutant));
  }
}

void FuzzTestMutator::SetMetadata(const ExecutionMetadata& metadata) {
  metadata.ForEachCmpEntry([](ByteSpan a, ByteSpan b) {
    size_t size = a.size();
    if (size < kMinCmpEntrySize) return;
    if (size > kMaxCmpEntrySize) return;
    // Use the memcmp table to avoid subtlety of the container domain mutation
    // with integer tables. E.g. it won't insert integer comparison data.
    fuzztest::internal::GetExecutionCoverage()
        ->GetTablesOfRecentCompares()
        .GetMutable<0>()
        .Insert(a.data(), b.data(), size);
  });
}

bool FuzzTestMutator::set_max_len(size_t max_len) {
  max_len_ = max_len;
  domain_->WithMaxSize(max_len);
  return true;
}

void FuzzTestMutator::AddToDictionary(
    const std::vector<ByteArray>& dict_entries) {
  domain_->WithDictionary(dict_entries);
}

}  // namespace centipede
