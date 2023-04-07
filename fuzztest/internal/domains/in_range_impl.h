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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_IN_RANGE_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_IN_RANGE_IMPL_H_

#include <cmath>
#include <cstddef>
#include <limits>
#include <optional>
#include <type_traits>

#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "./fuzztest/internal/coverage.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/value_mutation_helpers.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/table_of_recent_compares.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

template <typename T>
class InRangeImpl : public DomainBase<InRangeImpl<T>> {
 public:
  using typename InRangeImpl::DomainBase::value_type;

  constexpr static bool T_is_integer = std::numeric_limits<T>::is_integer;
  constexpr static bool T_is_signed = std::is_signed<T>::value;
  constexpr static bool T_is_memory_dictionary_compatible =
      std::is_integral_v<T> &&
      (sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8);
  using IntegerDictionaryT =
      std::conditional_t<T_is_memory_dictionary_compatible,
                         IntegerDictionary<T>, bool>;

  explicit InRangeImpl(T min, T max) : min_(min), max_(max) {
    FUZZTEST_INTERNAL_CHECK_PRECONDITION(min < max,
                                         "min must be smaller than max!");
    if constexpr (!T_is_integer) {
      FUZZTEST_INTERNAL_CHECK_PRECONDITION(
          !(min == std::numeric_limits<T>::lowest() &&
            max == std::numeric_limits<T>::max()),
          "Consider using the Finite<T>() domain instead.");
      FUZZTEST_INTERNAL_CHECK_PRECONDITION(std::isfinite(max - min),
                                           "Range is too large!");
    }
    if constexpr (T_is_integer) {
      // Find the longest common prefix
      // (from the most significant bit to the least significant bit) of
      // min_ and max_, and we only mutate the bits after the prefix.
      // This way it can somehow restrict the bit flipping range, but it
      // may still fail for range like [0b10000000, 0b01111111] which has
      // no valid bit flipping mutations.
      // We need to split the signed type range to positve range and
      // negative range because of their two's complement representation.
      if constexpr (T_is_signed) {
        if (min_ < 0 && max_ >= 0) {
          largest_mutable_bit_negative = BitWidth(~min);
          largest_mutable_bit_positive = BitWidth(max);
        } else if (min_ >= 0) {
          largest_mutable_bit_positive = BitWidth(min ^ max);
        } else if (max_ < 0) {
          largest_mutable_bit_negative = BitWidth(min ^ max);
        }
      } else {
        largest_mutable_bit_positive = BitWidth(min ^ max);
      }
    }
  }

  value_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    // TODO(sbenzaquen): Add more interesting points in the range.
    const T special[] = {min_, max_};
    return ChooseOneOr(special, prng, [&] {
      return absl::Uniform(absl::IntervalClosedClosed, prng, min_, max_);
    });
  }

  void Mutate(value_type& val, absl::BitGenRef prng, bool only_shrink) {
    permanent_dict_candidate_ = std::nullopt;
    if (val < min_ || val > max_) {
      val = Init(prng);
      return;
    }
    if (only_shrink) {
      // Shrink towards zero, limiting to the range.
      T limit;
      if (max_ <= T{0}) {
        limit = max_;
      } else if (min_ >= T{0}) {
        limit = min_;
      } else {
        limit = T{0};
      }
      if (val == limit) return;
      val = ShrinkTowards(prng, val, limit);
      return;
    }
    const T prev = val;
    do {
      // Randomly apply 3 types of mutations, similarly to Arbitrary.
      if constexpr (T_is_integer) {
        // Random bit flip.
        if constexpr (T_is_signed) {
          if (absl::Bernoulli(prng, 0.25)) {
            if (prev >= 0) {
              RandomBitFlip(prng, val, largest_mutable_bit_positive);
            } else {
              RandomBitFlip(prng, val, largest_mutable_bit_negative);
            }
            if (max_ < val || val < min_) {
              val = absl::Uniform(absl::IntervalClosedClosed, prng, min_, max_);
            }
          } else {
            RandomWalkOrUniformOrDict<5>(prng, val, min_, max_, temporary_dict_,
                                         permanent_dict_,
                                         permanent_dict_candidate_);
          }
        } else {
          if (absl::Bernoulli(prng, 0.25)) {
            RandomBitFlip(prng, val, largest_mutable_bit_positive);
            if (max_ < val || val < min_) {
              val = absl::Uniform(absl::IntervalClosedClosed, prng, min_, max_);
            }
          } else {
            RandomWalkOrUniformOrDict<5>(prng, val, min_, max_, temporary_dict_,
                                         permanent_dict_,
                                         permanent_dict_candidate_);
          }
        }
      } else {
        RandomWalkOrUniformOrDict<5>(prng, val, min_, max_, temporary_dict_,
                                     permanent_dict_,
                                     permanent_dict_candidate_);
      }
    } while (val == prev);  // Make sure Mutate really mutates.
  }

  std::optional<value_type> ParseCorpus(const IRObject& obj) const {
    auto as_corpus = obj.ToCorpus<value_type>();
    if (!as_corpus || *as_corpus > max_ || *as_corpus < min_) {
      return std::nullopt;
    }
    return as_corpus;
  }

  auto GetPrinter() const {
    if constexpr (std::numeric_limits<T>::is_integer) {
      return IntegralPrinter{};
    } else {
      return FloatingPrinter{};
    }
  }

  void UpdateMemoryDictionary(const value_type& val) {
    if constexpr (T_is_memory_dictionary_compatible) {
      if (GetExecutionCoverage() != nullptr) {
        temporary_dict_.MatchEntriesFromTableOfRecentCompares(
            val, GetExecutionCoverage()->GetTablesOfRecentCompares(), min_,
            max_);
        if (permanent_dict_candidate_.has_value() &&
            permanent_dict_.Size() < kPermanentDictMaxSize) {
          permanent_dict_.AddEntry(std::move(*permanent_dict_candidate_));
          permanent_dict_candidate_ = std::nullopt;
        }
      }
    }
  }

 private:
  T min_;
  T max_;
  size_t largest_mutable_bit_positive = 0;
  size_t largest_mutable_bit_negative = 0;
  IntegerDictionaryT temporary_dict_ = {};
  IntegerDictionaryT permanent_dict_ = {};
  std::optional<T> permanent_dict_candidate_ = std::nullopt;
  static constexpr size_t kPermanentDictMaxSize = 512;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_IN_RANGE_IMPL_H_
