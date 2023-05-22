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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ARBITRARY_FUNDAMENTAL_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ARBITRARY_FUNDAMENTAL_IMPL_H_

#include <limits>
#include <type_traits>

#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "./fuzztest/internal/coverage.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/value_mutation_helpers.h"
#include "./fuzztest/internal/table_of_recent_compares.h"

namespace fuzztest::internal {

// Fallback for error reporting, if T is not matched in Arbitrary<T>.
template <typename T, typename = void>
class ArbitraryImpl {
  static_assert(always_false<T>,
                "=> Type not supported yet. Consider filing an issue."
  );
};

// Arbitrary for monostate.
//
// For monostate types with a default constructor, just give the single value.
template <typename T>
class ArbitraryImpl<T, std::enable_if_t<is_monostate_v<T>>>
    : public DomainBase<ArbitraryImpl<T>> {
 public:
  using typename ArbitraryImpl::DomainBase::value_type;

  value_type Init(absl::BitGenRef) { return value_type{}; }

  void Mutate(value_type&, absl::BitGenRef, bool) {}

  bool ValidateCorpusValue(const value_type&) const {
    return true;  // Nothing to validate.
  }

  auto GetPrinter() const { return MonostatePrinter{}; }
};

// Arbitrary for bool.
template <>
class ArbitraryImpl<bool> : public DomainBase<ArbitraryImpl<bool>> {
 public:
  value_type Init(absl::BitGenRef prng) {
    if (auto seed = MaybeGetRandomSeed(prng)) return *seed;
    return static_cast<bool>(absl::Uniform(prng, 0, 2));
  }

  void Mutate(value_type& val, absl::BitGenRef, bool only_shrink) {
    if (only_shrink) {
      val = false;
    } else {
      val = !val;
    }
  }

  bool ValidateCorpusValue(const value_type&) const {
    return true;  // Nothing to validate.
  }

  auto GetPrinter() const { return IntegralPrinter{}; }
};

// Arbitrary for integers.
template <typename T>
class ArbitraryImpl<T, std::enable_if_t<!std::is_const_v<T> &&
                                        std::numeric_limits<T>::is_integer>>
    : public DomainBase<ArbitraryImpl<T>> {
 public:
  using typename ArbitraryImpl::DomainBase::value_type;

  static constexpr bool is_memory_dictionary_compatible_v =
      sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8;
  using IntegerDictionaryT =
      std::conditional_t<is_memory_dictionary_compatible_v,
                         IntegerDictionary<T>, bool>;

  value_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    const auto choose_from_all = [&] {
      return absl::Uniform(absl::IntervalClosedClosed, prng,
                           std::numeric_limits<T>::min(),
                           std::numeric_limits<T>::max());
    };
    if constexpr (sizeof(T) == 1) {
      return choose_from_all();
    } else {
      static constexpr T special[] = {
          T{0}, T{1},
          // For some types, ~T{} is promoted to int. Convert back to T.
          static_cast<T>(~T{}),
          std::numeric_limits<T>::is_signed
              ? std::numeric_limits<T>::max()
              : std::numeric_limits<T>::max() >> 1};
      return ChooseOneOr(special, prng, choose_from_all);
    }
  }

  void Mutate(value_type& val, absl::BitGenRef prng, bool only_shrink) {
    permanent_dict_candidate_ = std::nullopt;
    if (only_shrink) {
      if (val == 0) return;
      val = ShrinkTowards(prng, val, T{0});
      return;
    }
    const T prev = val;
    do {
      // Randomly apply 4 kinds of mutations with equal probabilities.
      // Use permanent_dictionary_ or temporary_dictionary_ with equal
      // probabilities.
      if (absl::Bernoulli(prng, 0.25)) {
        RandomBitFlip(prng, val, sizeof(T) * 8);
      } else {
        RandomWalkOrUniformOrDict<5>(prng, val, std::numeric_limits<T>::min(),
                                     std::numeric_limits<T>::max(),
                                     temporary_dict_, permanent_dict_,
                                     permanent_dict_candidate_);
      }
      // Make sure Mutate really mutates.
    } while (val == prev);
  }

  void UpdateMemoryDictionary(const value_type& val) {
    if constexpr (is_memory_dictionary_compatible_v) {
      if (GetExecutionCoverage() != nullptr) {
        temporary_dict_.MatchEntriesFromTableOfRecentCompares(
            val, GetExecutionCoverage()->GetTablesOfRecentCompares(),
            std::numeric_limits<T>::min(), std::numeric_limits<T>::max());
        if (permanent_dict_candidate_.has_value() &&
            permanent_dict_.Size() < kPermanentDictMaxSize) {
          permanent_dict_.AddEntry(std::move(*permanent_dict_candidate_));
          permanent_dict_candidate_ = std::nullopt;
        }
      }
    }
  }

  bool ValidateCorpusValue(const value_type&) const {
    return true;  // Nothing to validate.
  }

  auto GetPrinter() const { return IntegralPrinter{}; }

 private:
  // Matched snapshots from table of recent compares.
  // It's the "unverified" dictionary entries: the mutated
  // value matched something in this snapshot, but not sure
  // if it will lead to new coverage.
  IntegerDictionaryT temporary_dict_;
  // Set of dictionary entries from previous `temporary_dict_`
  // that leads to new coverage. This is based on a heuristic
  // that such entries may lead to interesting behaviors even
  // after the first new coverage it triggered.
  IntegerDictionaryT permanent_dict_;
  std::optional<T> permanent_dict_candidate_;
  static constexpr size_t kPermanentDictMaxSize = 512;
};

// Arbitrary for std::byte.
template <>
class ArbitraryImpl<std::byte> : public DomainBase<ArbitraryImpl<std::byte>> {
 public:
  using typename ArbitraryImpl::DomainBase::corpus_type;
  using typename ArbitraryImpl::DomainBase::value_type;

  value_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    return std::byte{inner_.Init(prng)};
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    unsigned char u8 = std::to_integer<unsigned char>(val);
    inner_.Mutate(u8, prng, only_shrink);
    val = std::byte{u8};
  }

  bool ValidateCorpusValue(const corpus_type&) const {
    return true;  // Nothing to validate.
  }

  auto GetPrinter() const { return IntegralPrinter{}; }

 private:
  ArbitraryImpl<unsigned char> inner_;
};

// Arbitrary for floats.
template <typename T>
class ArbitraryImpl<T, std::enable_if_t<std::is_floating_point_v<T>>>
    : public DomainBase<ArbitraryImpl<T>> {
 public:
  using typename ArbitraryImpl::DomainBase::value_type;

  value_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    const T special[] = {
        T{0.0}, T{-0.0}, T{1.0}, T{-1.0}, std::numeric_limits<T>::max(),
        std::numeric_limits<T>::infinity(), -std::numeric_limits<T>::infinity(),
        // std::nan is double. Cast to T explicitly.
        static_cast<T>(std::nan(""))};
    return ChooseOneOr(special, prng,
                       [&] { return absl::Uniform(prng, T{0}, T{1}); });
  }

  void Mutate(value_type& val, absl::BitGenRef prng, bool only_shrink) {
    if (only_shrink) {
      if (!std::isfinite(val) || val == 0) return;
      val = ShrinkTowards(prng, val, T{0});
      return;
    }
    const T prev = val;
    do {
      // If it is not finite we can't change it a bit because it would stay the
      // same. eg inf/2 == inf.
      if (!std::isfinite(val)) {
        val = Init(prng);
      } else {
        RunOne(
            prng,                    //
            [&] { val = val / 2; },  //
            [&] { val = -val; },     //
            [&] { val = val + 1; },  //
            [&] { val = val * 3; });
      }

      // Make sure Mutate really mutates.
    } while (val == prev || (std::isnan(prev) && std::isnan(val)));
  }

  bool ValidateCorpusValue(const value_type&) const {
    return true;  // Nothing to validate.
  }

  auto GetPrinter() const { return FloatingPrinter{}; }
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ARBITRARY_FUNDAMENTAL_IMPL_H_
