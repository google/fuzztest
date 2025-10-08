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
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "absl/random/random.h"
#include "absl/types/span.h"
#include "./centipede/byte_array_mutator.h"
#include "./centipede/execution_metadata.h"
#include "./centipede/knobs.h"
#include "./centipede/mutation_input.h"
#include "./common/defs.h"
#include "./common/logging.h"
#include "./fuzztest/domain_core.h"
#include "./fuzztest/internal/table_of_recent_compares.h"

namespace fuzztest::internal {

namespace {

using MutatorDomainBase =
    decltype(fuzztest::VectorOf(fuzztest::Arbitrary<uint8_t>()));

template <typename T>
void InsertCmpEntryIntoIntegerDictionary(const uint8_t* a, const uint8_t* b,
                                         TablesOfRecentCompares& cmp_tables) {
  T a_int;
  T b_int;
  std::memcpy(&a_int, a, sizeof(T));
  std::memcpy(&b_int, b, sizeof(T));
  cmp_tables.GetMutable<sizeof(T)>().Insert(a_int, b_int);
}

}  // namespace

void PopulateCmpEntries(const ExecutionMetadata& metadata,
                        TablesOfRecentCompares& cmp_tables) {
  // Size limits on the cmp entries to be populated.
  static constexpr uint8_t kMaxCmpEntrySize = 15;
  static constexpr uint8_t kMinCmpEntrySize = 2;

  metadata.ForEachCmpEntry([&cmp_tables](fuzztest::internal::ByteSpan a,
                                         fuzztest::internal::ByteSpan b) {
    FUZZTEST_CHECK(a.size() == b.size())
        << "cmp operands must have the same size";
    const size_t size = a.size();
    if (size < kMinCmpEntrySize) return;
    if (size > kMaxCmpEntrySize) return;
    if (size == 2) {
      InsertCmpEntryIntoIntegerDictionary<uint16_t>(a.data(), b.data(),
                                                    cmp_tables);
    } else if (size == 4) {
      InsertCmpEntryIntoIntegerDictionary<uint32_t>(a.data(), b.data(),
                                                    cmp_tables);
    } else if (size == 8) {
      InsertCmpEntryIntoIntegerDictionary<uint64_t>(a.data(), b.data(),
                                                    cmp_tables);
    }
    cmp_tables.GetMutable<0>().Insert(a.data(), b.data(), size);
  });
}

struct FuzzTestMutator::MutationMetadata {
  std::vector<std::optional<fuzztest::internal::TablesOfRecentCompares>>
      cmp_tables;
};

class FuzzTestMutator::MutatorDomain : public MutatorDomainBase {
 public:
  MutatorDomain()
      : MutatorDomainBase(fuzztest::VectorOf(fuzztest::Arbitrary<uint8_t>())) {}

  ~MutatorDomain() {}
};

FuzzTestMutator::FuzzTestMutator(const Knobs &knobs, uint64_t seed)
    : knobs_(knobs),
      prng_(seed),
      mutation_metadata_(std::make_unique<MutationMetadata>()),
      domain_(std::make_unique<MutatorDomain>()) {
  domain_->WithMinSize(1).WithMaxSize(max_len_);
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

std::vector<ByteArray> FuzzTestMutator::MutateMany(
    const std::vector<MutationInputRef> &inputs, size_t num_mutants) {
  if (inputs.empty()) abort();
  auto& cmp_tables = mutation_metadata_->cmp_tables;
  cmp_tables.resize(inputs.size());
  std::vector<ByteArray> mutants;
  mutants.reserve(num_mutants);
  for (int i = 0; i < num_mutants; ++i) {
    auto index = absl::Uniform<size_t>(prng_, 0, inputs.size());
    if (!cmp_tables[index].has_value() && inputs[index].metadata != nullptr) {
      cmp_tables[index].emplace(/*compact=*/true);
      PopulateCmpEntries(*inputs[index].metadata, *cmp_tables[index]);
    }
    auto mutant = inputs[index].data;
    if (mutant.size() > max_len_) mutant.resize(max_len_);
    if (knobs_.GenerateBool(knob_mutate_or_crossover, prng_())) {
      // Perform crossover with some other input. It may be the same input.
      const auto &other_input =
          inputs[absl::Uniform<size_t>(prng_, 0, inputs.size())].data;
      CrossOver(mutant, other_input);
    } else {
      domain_->Mutate(
          mutant, prng_,
          {/*cmp_tables=*/cmp_tables[index].has_value() ? &*cmp_tables[index]
                                                        : nullptr},
          /*only_shrink=*/false);
    }
    mutants.push_back(std::move(mutant));
  }
  cmp_tables.clear();
  return mutants;
}

bool FuzzTestMutator::set_max_len(size_t max_len) {
  max_len_ = max_len;
  domain_->WithMaxSize(max_len);
  return true;
}

void FuzzTestMutator::AddToDictionary(
    const std::vector<ByteArray> &dict_entries) {
  domain_->WithDictionary(dict_entries);
}

}  // namespace fuzztest::internal
