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
#include "./fuzztest/internal/domains/arbitrary_fundamental_impl.h"
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

// Arbitrary for containers.
template <typename T>
class ArbitraryImpl<
    T,
    std::enable_if_t<always_true<T>,
                     decltype(
                         // Iterable
                         T().begin(), T().end(), T().size(),
                         // Values are mutable
                         // This rejects associative containers, for example
                         // *T().begin() = std::declval<value_type_t<T>>(),
                         // Can insert and erase elements
                         T().insert(T().end(), std::declval<value_type_t<T>>()),
                         T().erase(T().begin()),
                         //
                         (void)0)>>
    : public ContainerOfImpl<T, ArbitraryImpl<value_type_t<T>>> {};

// Arbitrary for std::string_view.
//
// We define a separate container for string_view, to detect out of bounds bugs
// better. See below.
template <typename Char>
class ArbitraryImpl<std::basic_string_view<Char>>
    : public DomainBase<ArbitraryImpl<std::basic_string_view<Char>>,
                        std::basic_string_view<Char>,
                        // We use a vector to better manage the buffer and help
                        // ASan find out-of-bounds bugs.
                        std::vector<Char>> {
 public:
  using typename ArbitraryImpl::DomainBase::corpus_type;
  using typename ArbitraryImpl::DomainBase::value_type;

  corpus_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    return inner_.Init(prng);
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    inner_.Mutate(val, prng, only_shrink);
  }

  void UpdateMemoryDictionary(const corpus_type& val) {
    inner_.UpdateMemoryDictionary(val);
  }

  auto GetPrinter() const { return StringPrinter{}; }

  value_type GetValue(const corpus_type& value) const {
    return value_type(value.data(), value.size());
  }

  std::optional<corpus_type> FromValue(const value_type& value) const {
    return corpus_type(value.begin(), value.end());
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    return obj.ToCorpus<corpus_type>();
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return IRObject::FromCorpus(v);
  }

  bool ValidateCorpusValue(const corpus_type&) const {
    return true;  // Nothing to validate.
  }

 private:
  ArbitraryImpl<std::vector<Char>> inner_;
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
AggregateOfImpl<T, RequireCustomCorpusType::kYes, ArbitraryImpl<Elem>...>
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
              ? RequireCustomCorpusType::kYes
              : RequireCustomCorpusType::kNo,
          ArbitraryImpl<T>, ArbitraryImpl<U>> {};

// Arbitrary for std::tuple.
template <typename... T>
class ArbitraryImpl<std::tuple<T...>, std::enable_if_t<sizeof...(T) != 0>>
    : public AggregateOfImpl<std::tuple<T...>, RequireCustomCorpusType::kNo,
                             ArbitraryImpl<T>...> {};

// Arbitrary for std::array.
template <typename T, size_t N>
auto AggregateOfImplForArray() {
  return ApplyIndex<N>([&](auto... I) {
    return AggregateOfImpl<std::array<T, N>, RequireCustomCorpusType::kNo,
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
