// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_BIT_FLAG_COMBINATION_OF_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_BIT_FLAG_COMBINATION_OF_IMPL_H_

#include <type_traits>
#include <vector>

#include "absl/random/bit_gen_ref.h"
#include "absl/types/span.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

template <typename T>
class BitFlagCombinationOfImpl
    : public DomainBase<BitFlagCombinationOfImpl<T>> {
 public:
  using typename BitFlagCombinationOfImpl::DomainBase::value_type;

  explicit BitFlagCombinationOfImpl(absl::Span<const T> flags)
      : flags_(flags.begin(), flags.end()) {
    FUZZTEST_INTERNAL_CHECK_PRECONDITION(
        !flags.empty(), "BitFlagCombinationOf requires a non empty list.");
    // Make sure they are mutually exclusive options, and none are empty.
    for (int i = 0; i < flags.size(); ++i) {
      T v1 = flags[i];
      FUZZTEST_INTERNAL_CHECK_PRECONDITION(
          v1 != T{}, "BitFlagCombinationOf requires non zero flags.");
      for (int j = i + 1; j < flags.size(); ++j) {
        T v2 = flags[j];
        FUZZTEST_INTERNAL_CHECK_PRECONDITION(
            BitAnd(v1, v2) == T{},
            "BitFlagCombinationOf requires flags to be mutually exclusive.");
      }
    }
  }

  value_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    return value_type{};
  }

  void Mutate(value_type& val, absl::BitGenRef prng, bool only_shrink) {
    T to_switch = flags_[ChooseOffset(flags_.size(), prng)];

    if (!only_shrink || BitAnd(val, to_switch) != T{}) {
      val = BitXor(val, to_switch);
    }
  }

  absl::Status ValidateCorpusValue(const value_type&) const {
    return absl::OkStatus();
  }

  auto GetPrinter() const { return AutodetectTypePrinter<T>(); }

 private:
  template <typename U>
  static value_type BitAnd(U a, U b) {
    if constexpr (std::is_enum_v<U>) {
      return BitAnd(static_cast<std::underlying_type_t<U>>(a),
                    static_cast<std::underlying_type_t<U>>(b));
    } else {
      return static_cast<value_type>(a & b);
    }
  }

  template <typename U>
  static value_type BitXor(U a, U b) {
    if constexpr (std::is_enum_v<U>) {
      return BitXor(static_cast<std::underlying_type_t<U>>(a),
                    static_cast<std::underlying_type_t<U>>(b));
    } else {
      return static_cast<value_type>(a ^ b);
    }
  }

  std::vector<value_type> flags_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_BIT_FLAG_COMBINATION_OF_IMPL_H_
