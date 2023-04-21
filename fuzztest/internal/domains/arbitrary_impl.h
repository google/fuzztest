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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ARBITRARY_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ARBITRARY_IMPL_H_

#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "absl/time/time.h"
#include "./fuzztest/internal/coverage.h"
#include "./fuzztest/internal/domains/absl_helpers.h"
#include "./fuzztest/internal/domains/aggregate_of_impl.h"
#include "./fuzztest/internal/domains/container_of_impl.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/element_of_impl.h"
#include "./fuzztest/internal/domains/in_range_impl.h"
#include "./fuzztest/internal/domains/map_impl.h"
#include "./fuzztest/internal/domains/one_of_impl.h"
#include "./fuzztest/internal/domains/optional_of_impl.h"
#include "./fuzztest/internal/domains/smart_pointer_of_impl.h"
#include "./fuzztest/internal/domains/value_mutation_helpers.h"
#include "./fuzztest/internal/domains/variant_of_impl.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/table_of_recent_compares.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

// Fallback for error reporting, if T is not matched in Arbitrary<T>.
template <typename UserValueT, typename = void>
class ArbitraryImpl {
  static_assert(always_false<UserValueT>,
                "=> Type not supported yet. Consider filing an issue."
  );
};

// Arbitrary for monostate.
//
// For monostate types with a default constructor, just give the single value.
template <typename MonoT>
class ArbitraryImpl<MonoT, std::enable_if_t<is_monostate_v<MonoT>>>
    : public DomainBase<ArbitraryImpl<MonoT>> {
 public:
  using typename ArbitraryImpl::DomainBase::user_value_t;

  user_value_t Init(absl::BitGenRef) { return user_value_t{}; }

  void Mutate(user_value_t&, absl::BitGenRef, bool) {}

  bool ValidateCorpusValue(const user_value_t&) const {
    return true;  // Nothing to validate.
  }

  auto GetPrinter() const { return MonostatePrinter{}; }
};

// Arbitrary for bool.
template <>
class ArbitraryImpl<bool> : public DomainBase<ArbitraryImpl<bool>> {
 public:
  user_value_t Init(absl::BitGenRef prng) {
    if (auto seed = MaybeGetRandomSeed(prng)) return *seed;
    return static_cast<bool>(absl::Uniform(prng, 0, 2));
  }

  void Mutate(user_value_t& val, absl::BitGenRef, bool only_shrink) {
    if (only_shrink) {
      val = false;
    } else {
      val = !val;
    }
  }

  bool ValidateCorpusValue(const user_value_t&) const {
    return true;  // Nothing to validate.
  }

  auto GetPrinter() const { return IntegralPrinter{}; }
};

// Arbitrary for integers.
template <typename IntegerT>
class ArbitraryImpl<IntegerT,
                    std::enable_if_t<!std::is_const_v<IntegerT> &&
                                     std::numeric_limits<IntegerT>::is_integer>>
    : public DomainBase<ArbitraryImpl<IntegerT>> {
 public:
  using typename ArbitraryImpl::DomainBase::user_value_t;

  static constexpr bool is_memory_dictionary_compatible_v =
      sizeof(IntegerT) == 1 || sizeof(IntegerT) == 2 || sizeof(IntegerT) == 4 ||
      sizeof(IntegerT) == 8;
  using IntegerDictionaryT =
      std::conditional_t<is_memory_dictionary_compatible_v,
                         IntegerDictionary<IntegerT>, bool>;

  user_value_t Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    const auto choose_from_all = [&] {
      return absl::Uniform(absl::IntervalClosedClosed, prng,
                           std::numeric_limits<IntegerT>::min(),
                           std::numeric_limits<IntegerT>::max());
    };
    if constexpr (sizeof(IntegerT) == 1) {
      return choose_from_all();
    } else {
      static constexpr IntegerT special[] = {
          IntegerT{0}, IntegerT{1},
          // For some types, ~T{} is promoted to int. Convert back to T.
          static_cast<IntegerT>(~IntegerT{}),
          std::numeric_limits<IntegerT>::is_signed
              ? std::numeric_limits<IntegerT>::max()
              : std::numeric_limits<IntegerT>::max() >> 1};
      return ChooseOneOr(special, prng, choose_from_all);
    }
  }

  void Mutate(user_value_t& val, absl::BitGenRef prng, bool only_shrink) {
    permanent_dict_candidate_ = std::nullopt;
    if (only_shrink) {
      if (val == 0) return;
      val = ShrinkTowards(prng, val, IntegerT{0});
      return;
    }
    const IntegerT prev = val;
    do {
      // Randomly apply 4 kinds of mutations with equal probabilities.
      // Use permanent_dictionary_ or temporary_dictionary_ with equal
      // probabilities.
      if (absl::Bernoulli(prng, 0.25)) {
        RandomBitFlip(prng, val, sizeof(IntegerT) * 8);
      } else {
        RandomWalkOrUniformOrDict<5>(
            prng, val, std::numeric_limits<IntegerT>::min(),
            std::numeric_limits<IntegerT>::max(), temporary_dict_,
            permanent_dict_, permanent_dict_candidate_);
      }
      // Make sure Mutate really mutates.
    } while (val == prev);
  }

  void UpdateMemoryDictionary(const user_value_t& val) {
    if constexpr (is_memory_dictionary_compatible_v) {
      if (GetExecutionCoverage() != nullptr) {
        temporary_dict_.MatchEntriesFromTableOfRecentCompares(
            val, GetExecutionCoverage()->GetTablesOfRecentCompares(),
            std::numeric_limits<IntegerT>::min(),
            std::numeric_limits<IntegerT>::max());
        if (permanent_dict_candidate_.has_value() &&
            permanent_dict_.Size() < kPermanentDictMaxSize) {
          permanent_dict_.AddEntry(std::move(*permanent_dict_candidate_));
          permanent_dict_candidate_ = std::nullopt;
        }
      }
    }
  }

  bool ValidateCorpusValue(const user_value_t&) const {
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
  std::optional<IntegerT> permanent_dict_candidate_;
  static constexpr size_t kPermanentDictMaxSize = 512;
};

// Arbitrary for floats.
template <typename FloatT>
class ArbitraryImpl<FloatT, std::enable_if_t<std::is_floating_point_v<FloatT>>>
    : public DomainBase<ArbitraryImpl<FloatT>> {
 public:
  using typename ArbitraryImpl::DomainBase::user_value_t;

  user_value_t Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    const FloatT special[] = {FloatT{0.0}, FloatT{-0.0}, FloatT{1.0},
                              FloatT{-1.0}, std::numeric_limits<FloatT>::max(),
                              std::numeric_limits<FloatT>::infinity(),
                              -std::numeric_limits<FloatT>::infinity(),
                              // std::nan is double. Cast to T explicitly.
                              static_cast<FloatT>(std::nan(""))};
    return ChooseOneOr(special, prng, [&] {
      return absl::Uniform(prng, FloatT{0}, FloatT{1});
    });
  }

  void Mutate(user_value_t& val, absl::BitGenRef prng, bool only_shrink) {
    if (only_shrink) {
      if (!std::isfinite(val) || val == 0) return;
      val = ShrinkTowards(prng, val, FloatT{0});
      return;
    }
    const FloatT prev = val;
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

  bool ValidateCorpusValue(const user_value_t&) const {
    return true;  // Nothing to validate.
  }

  auto GetPrinter() const { return FloatingPrinter{}; }
};

// Arbitrary for containers.
template <typename ContainerT>
class ArbitraryImpl<
    ContainerT,
    std::enable_if_t<always_true<ContainerT>,
                     decltype(
                         // Iterable:
                         ContainerT().begin(), ContainerT().end(),
                         ContainerT().size(),
                         // Values are mutable:
                         // This rejects associative containers, for example
                         // *ContainerT().begin() = std::declval<typename
                         // ContainerT::value_type>(),
                         // Can insert and erase elements:
                         ContainerT().insert(
                             ContainerT().end(),
                             std::declval<typename ContainerT::value_type>()),
                         ContainerT().erase(ContainerT().begin()),
                         //
                         (void)0)>>
    : public ContainerOfImpl<ContainerT,
                             ArbitraryImpl<typename ContainerT::value_type>> {};

// Arbitrary for std::string_view.
//
// We define a separate container for string_view, to detect out of bounds bugs
// better. See below.
template <typename CharT>
class ArbitraryImpl<std::basic_string_view<CharT>>
    : public DomainBase<ArbitraryImpl<std::basic_string_view<CharT>>,
                        std::basic_string_view<CharT>,
                        // We use a vector to better manage the buffer and help
                        // ASan find out-of-bounds bugs.
                        std::vector<CharT>> {
 public:
  using typename ArbitraryImpl::DomainBase::corpus_value_t;
  using typename ArbitraryImpl::DomainBase::user_value_t;

  corpus_value_t Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    return inner_.Init(prng);
  }

  void Mutate(corpus_value_t& val, absl::BitGenRef prng, bool only_shrink) {
    inner_.Mutate(val, prng, only_shrink);
  }

  void UpdateMemoryDictionary(const corpus_value_t& val) {
    inner_.UpdateMemoryDictionary(val);
  }

  auto GetPrinter() const { return StringPrinter{}; }

  user_value_t CorpusToUserValue(const corpus_value_t& value) const {
    return user_value_t(value.data(), value.size());
  }

  std::optional<corpus_value_t> UserToCorpusValue(
      const user_value_t& value) const {
    return corpus_value_t(value.begin(), value.end());
  }

  std::optional<corpus_value_t> IrToCorpusValue(const IrValue& ir) const {
    return ir.ToCorpus<corpus_value_t>();
  }

  IrValue CorpusToIrValue(const corpus_value_t& v) const {
    return IrValue::FromCorpus(v);
  }

  bool ValidateCorpusValue(const corpus_value_t&) const {
    return true;  // Nothing to validate.
  }

 private:
  ArbitraryImpl<std::vector<CharT>> inner_;
};

// Arbitrary for any const T.
//
// We capture const types as a workaround in order to enable
// Arbitrary<std::map<std::string, int>>() and similar container domains that
// require Arbitrary<std::pair< _const_ std::string, int>>() to be defined,
// which in turn requires Arbitrary<const std::string>() to be defined.
template <typename T>
class ArbitraryImpl<const T> : public ArbitraryImpl<T> {};

// Arbitrary for user-defined aggregate types (structs/classes).

template <typename T, typename... Elem>
AggregateOfImpl<T, RequireCustomCorpusValueT::kYes, ArbitraryImpl<Elem>...>
    DetectAggregateOfImpl2(std::tuple<Elem&...>);

// Detect the number and types of the fields.
// TODO(sbenzaquen): Verify the compiler error in case we can't detect it and
// improve if possible.
template <typename T, int N = *DetectBindableFieldCount<T>()>
decltype(DetectAggregateOfImpl2<T>(
    BindAggregate(std::declval<T&>(), std::integral_constant<int, N>{})))
DetectAggregateOfImpl();

template <typename T>
class ArbitraryImpl<
    T, std::enable_if_t<std::is_class_v<T> && std::is_aggregate_v<T> &&
                        // Monostates have their own domain.
                        !is_monostate_v<T> &&
                        // std::array uses the Tuple domain.
                        !is_array_v<T>>>
    : public decltype(DetectAggregateOfImpl<T>()) {};

// Arbitrary for std::pair.
template <typename T, typename U>
class ArbitraryImpl<std::pair<T, U>>
    : public AggregateOfImpl<
          std::pair<std::remove_const_t<T>, std::remove_const_t<U>>,
          std::is_const_v<T> || std::is_const_v<U>
              ? RequireCustomCorpusValueT::kYes
              : RequireCustomCorpusValueT::kNo,
          ArbitraryImpl<T>, ArbitraryImpl<U>> {};

// Arbitrary for std::tuple.
template <typename... T>
class ArbitraryImpl<std::tuple<T...>, std::enable_if_t<sizeof...(T) != 0>>
    : public AggregateOfImpl<std::tuple<T...>, RequireCustomCorpusValueT::kNo,
                             ArbitraryImpl<T>...> {};

// Arbitrary for std::array.
template <typename T, size_t N>
auto AggregateOfImplForArray() {
  return ApplyIndex<N>([&](auto... I) {
    return AggregateOfImpl<std::array<T, N>, RequireCustomCorpusValueT::kNo,
                           std::enable_if_t<(I >= 0), ArbitraryImpl<T>>...>{};
  });
}
template <typename T, size_t N>
class ArbitraryImpl<std::array<T, N>>
    : public decltype(AggregateOfImplForArray<T, N>()) {};

// Arbitrary for std::variant.
template <typename... T>
class ArbitraryImpl<std::variant<T...>>
    : public VariantOfImpl<std::variant<T...>, ArbitraryImpl<T>...> {};

// Arbitrary for std::optional.
template <typename T>
class ArbitraryImpl<std::optional<T>>
    : public OptionalOfImpl<std::optional<T>, ArbitraryImpl<T>> {
 public:
  ArbitraryImpl() : ArbitraryImpl::OptionalOfImpl(ArbitraryImpl<T>()) {}
};

// Used by Arbitrary std::unique_ptr / std::shared_ptr.
template <typename T>
const Domain<T>& GetGlobalDomainDefaultInstance() {
  static const auto* instance = new Domain<T>(ArbitraryImpl<T>());
  return *instance;
}

// Arbitrary for std::unique_ptr.
template <typename T>
class ArbitraryImpl<std::unique_ptr<T>>
    : public SmartPointerOfImpl<std::unique_ptr<T>, ArbitraryImpl<T>> {
 public:
  ArbitraryImpl()
      : ArbitraryImpl::SmartPointerOfImpl(GetGlobalDomainDefaultInstance) {}
};

// Arbitrary for std::shared_ptr.
template <typename T>
class ArbitraryImpl<std::shared_ptr<T>>
    : public SmartPointerOfImpl<std::shared_ptr<T>, ArbitraryImpl<T>> {
 public:
  ArbitraryImpl()
      : ArbitraryImpl::SmartPointerOfImpl(GetGlobalDomainDefaultInstance) {}
};

// Arbitrary for absl::Duration.
template <>
class ArbitraryImpl<absl::Duration>
    : public OneOfImpl<ElementOfImpl<absl::Duration>,
                       MapImpl<absl::Duration (*)(int64_t, uint32_t),
                               ArbitraryImpl<int64_t>, InRangeImpl<uint32_t>>> {
 public:
  ArbitraryImpl()
      : OneOfImpl(
            ElementOfImpl<absl::Duration>(
                {absl::InfiniteDuration(), -absl::InfiniteDuration()}),
            MapImpl<absl::Duration (*)(int64_t, uint32_t),
                    ArbitraryImpl<int64_t>, InRangeImpl<uint32_t>>(
                [](int64_t secs, uint32_t ticks) {
                  return MakeDuration(secs, ticks);
                },
                ArbitraryImpl<int64_t>(),
                // ticks is 1/4 of a nanosecond and has a range of [0, 4B - 1]
                InRangeImpl<uint32_t>(0u, 3'999'999'999u))) {}
};

// Arbitrary for absl::Time.
template <>
class ArbitraryImpl<absl::Time>
    : public MapImpl<absl::Time (*)(absl::Duration),
                     ArbitraryImpl<absl::Duration>> {
 public:
  ArbitraryImpl()
      : MapImpl<absl::Time (*)(absl::Duration), ArbitraryImpl<absl::Duration>>(
            [](absl::Duration duration) {
              return absl::UnixEpoch() + duration;
            },
            ArbitraryImpl<absl::Duration>()) {}
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ARBITRARY_IMPL_H_
