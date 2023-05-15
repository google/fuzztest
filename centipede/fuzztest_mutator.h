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

#ifndef THIRD_PARTY_CENTIPEDE_FUZZTEST_MUTATOR_H_
#define THIRD_PARTY_CENTIPEDE_FUZZTEST_MUTATOR_H_

#include <vector>

#include "absl/random/random.h"
#include "./centipede/defs.h"
#include "./fuzztest/internal/domains/container_of_impl.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/value_mutation_helpers.h"
#include "./fuzztest/internal/type_support.h"

namespace centipede {

// Domain for arbitrary byte.
class ArbitraryByte
    : public fuzztest::internal::DomainBase<ArbitraryByte, uint8_t> {
 public:
  using typename ArbitraryByte::DomainBase::value_type;

  static constexpr bool is_memory_dictionary_compatible_v = true;

  value_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    return absl::Uniform(absl::IntervalClosedClosed, prng,
                         std::numeric_limits<value_type>::min(),
                         std::numeric_limits<value_type>::max());
  }

  void Mutate(value_type &val, absl::BitGenRef prng, bool only_shrink) {
    if (only_shrink) {
      if (val == 0) return;
      val = fuzztest::internal::ShrinkTowards(prng, val, value_type{0});
      return;
    }
    const value_type prev = val;
    do {
      fuzztest::internal::RandomBitFlip(prng, val, sizeof(value_type) * 8);
      // Make sure Mutate really mutates.
    } while (val == prev);
  }

  bool ValidateCorpusValue(const value_type &) const {
    return true;  // Nothing to validate.
  }

  auto GetPrinter() const { return fuzztest::internal::IntegralPrinter{}; }

 private:
};

class FuzzTestMutator {
 public:
  // Initialize the mutator with given `seed`.
  FuzzTestMutator(uintptr_t seed);

  // Takes non-empty `inputs`, produces `num_mutants` mutations in `mutants`.
  // Old contents of `mutants` are discarded.
  void MutateMany(const std::vector<ByteArray> &inputs, size_t num_mutants,
                  std::vector<ByteArray> &mutants);

  // Adds `dict_entries` to an internal dictionary.
  void AddToDictionary(const std::vector<ByteArray> &dict_entries);

  // Size limits on the cmp entries to be used in mutation.
  static constexpr uint8_t kMaxCmpEntrySize = 15;
  static constexpr uint8_t kMinCmpEntrySize = 2;

  // Calls SetFromCmpData(cmp_data) on the internal CmpDictionary.
  // Returns false on failure, true otherwise.
  bool SetCmpDictionary(ByteSpan cmp_data);

  bool set_size_alignment(size_t size_alignment) {
    // TODO(xinhaoyuan): Implement size alignment.
    return true;
  }

  bool set_max_len(size_t max_len) {
    domain_.WithMaxSize(max_len);
    return true;
  }

 private:
  absl::BitGen prng_;
  decltype(fuzztest::internal::ContainerOfImpl<std::vector<uint8_t>,
                                               ArbitraryByte>(
      ArbitraryByte())) domain_;
};

}  // namespace centipede

#endif
