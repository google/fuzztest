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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_AGGREGATE_OF_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_AGGREGATE_OF_IMPL_H_

#include <array>
#include <cstddef>
#include <optional>
#include <tuple>
#include <type_traits>
#include <utility>

#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "absl/strings/str_format.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/serialization_helpers.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

enum class RequireCustomCorpusValueT { kNo, kYes };

// For user defined types (structs) we require a custom corpus_value_t
// (std::tuple), because the serializer does not support structs, only tuples.
template <typename UserValueT, RequireCustomCorpusValueT require_custom,
          typename... InnerDomains>
using AggregateOfImplCorpusValueT =
    std::conditional_t<require_custom == RequireCustomCorpusValueT::kYes ||
                           (InnerDomains::has_custom_corpus_value_t || ...),
                       std::tuple<corpus_value_t_of<InnerDomains>...>,
                       UserValueT>;

template <typename UserValueT, RequireCustomCorpusValueT require_custom,
          typename... InnerDomains>
class AggregateOfImpl
    : public DomainBase<
          AggregateOfImpl<UserValueT, require_custom, InnerDomains...>,
          UserValueT,
          /*CorpusValueT=*/
          AggregateOfImplCorpusValueT<UserValueT, require_custom,
                                      InnerDomains...>> {
 public:
  using AggregateOfImpl::DomainBase::has_custom_corpus_value_t;
  using typename AggregateOfImpl::DomainBase::corpus_value_t;
  using typename AggregateOfImpl::DomainBase::user_value_t;

  AggregateOfImpl() = default;
  explicit AggregateOfImpl(std::in_place_t, InnerDomains... inner)
      : inner_(std::move(inner)...) {}

  corpus_value_t Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    return std::apply(
        [&](auto&... inner) { return corpus_value_t{inner.Init(prng)...}; },
        inner_);
  }

  void Mutate(corpus_value_t& val, absl::BitGenRef prng, bool only_shrink) {
    std::integral_constant<int, sizeof...(InnerDomains)> size;
    auto bound = internal::BindAggregate(val, size);
    // Filter the tuple to only the mutable fields.
    // The const ones can't be mutated.
    // Eg in `std::pair<const int, int>` for maps.
    static constexpr auto to_mutate =
        GetMutableSubtuple<decltype(internal::BindAggregate(
            std::declval<UserValueT&>(), size))>();
    static constexpr size_t actual_size =
        std::tuple_size_v<decltype(to_mutate)>;
    if constexpr (actual_size > 0) {
      int offset = absl::Uniform<int>(prng, 0, actual_size);
      Switch<actual_size>(offset, [&](auto I) {
        std::get<to_mutate[I]>(inner_).Mutate(std::get<to_mutate[I]>(bound),
                                              prng, only_shrink);
      });
    }
  }

  void UpdateMemoryDictionary(const corpus_value_t& val) {
    // Copy codes from Mutate that does the mutable domain filtering things.
    std::integral_constant<int, sizeof...(InnerDomains)> size;
    auto bound = internal::BindAggregate(val, size);
    static constexpr auto to_mutate =
        GetMutableSubtuple<decltype(internal::BindAggregate(
            std::declval<UserValueT&>(), size))>();
    static constexpr size_t actual_size =
        std::tuple_size_v<decltype(to_mutate)>;
    // Apply UpdateMemoryDictionary to every mutable domain.
    if constexpr (actual_size > 0) {
      ApplyIndex<actual_size>([&](auto... I) {
        (std::get<to_mutate[I]>(inner_).UpdateMemoryDictionary(
             std::get<to_mutate[I]>(bound)),
         ...);
      });
    }
  }

  int UntypedPrintCorpusValue(const GenericCorpusValue& val,
                              absl::FormatRawSink out, internal::PrintMode mode,
                              std::optional<int> tuple_elem) const final {
    if (tuple_elem.has_value()) {
      if constexpr (sizeof...(InnerDomains) != 0) {
        if (*tuple_elem >= 0 && *tuple_elem < sizeof...(InnerDomains)) {
          Switch<sizeof...(InnerDomains)>(*tuple_elem, [&](auto I) {
            PrintValue(std::get<I>(inner_),
                       std::get<I>(val.GetAs<corpus_value_t>()), out, mode);
          });
        }
      }
    } else {
      AggregateOfImpl::DomainBase::UntypedPrintCorpusValue(val, out, mode,
                                                           std::nullopt);
    }
    return sizeof...(InnerDomains);
  }

  auto GetPrinter() const { return AggregatePrinter<InnerDomains...>{inner_}; }

  user_value_t CorpusToUserValue(const corpus_value_t& value) const {
    if constexpr (has_custom_corpus_value_t) {
      if constexpr (DetectBindableFieldCount<user_value_t>() ==
                    DetectBraceInitCount<user_value_t>()) {
        return ApplyIndex<sizeof...(InnerDomains)>([&](auto... I) {
          return UserValueT{
              std::get<I>(inner_).CorpusToUserValue(std::get<I>(value))...};
        });
      } else {
        // Right now the only other possibility is that the bindable field count
        // is one less than the brace init field count. In that case, that extra
        // field is used to initialize an empty base class. We'll need to update
        // this if that ever changes.
        return ApplyIndex<sizeof...(InnerDomains)>([&](auto... I) {
          return UserValueT{
              {}, std::get<I>(inner_).CorpusToUserValue(std::get<I>(value))...};
        });
      }
    } else {
      return value;
    }
  }

  std::optional<corpus_value_t> UserToCorpusValue(
      const user_value_t& value) const {
    if constexpr (has_custom_corpus_value_t) {
      return ApplyIndex<sizeof...(InnerDomains)>([&](auto... I) {
        auto bound = internal::BindAggregate(
            value, std::integral_constant<int, sizeof...(InnerDomains)>{});
        return [](auto... optional_values) -> std::optional<corpus_value_t> {
          if ((optional_values.has_value() && ...)) {
            return std::tuple(*std::move(optional_values)...);
          } else {
            return std::nullopt;
          }
        }(std::get<I>(inner_).UserToCorpusValue(std::get<I>(bound))...);
      });
    } else {
      return value;
    }
  }

  // Use the generic serializer when no custom corpus type is used, since it is
  // more efficient. Eg a string value can be serialized as a string instead of
  // as a sequence of char values.
  std::optional<corpus_value_t> IrToCorpusValue(const IrValue& ir) const {
    if constexpr (has_custom_corpus_value_t) {
      return ParseWithDomainTuple(inner_, ir);
    } else {
      return ir.ToCorpus<corpus_value_t>();
    }
  }

  IrValue CorpusToIrValue(const corpus_value_t& v) const {
    if constexpr (has_custom_corpus_value_t) {
      return SerializeWithDomainTuple(inner_, v);
    } else {
      return IrValue::FromCorpus(v);
    }
  }

  bool ValidateCorpusValue(const corpus_value_t& corpus_value) const {
    return ApplyIndex<sizeof...(InnerDomains)>([&](auto... I) {
      return (
          std::get<I>(inner_).ValidateCorpusValue(std::get<I>(corpus_value)) &&
          ...);
    });
  }

 private:
  template <typename Tuple>
  static constexpr auto GetMutableSubtuple() {
    return ApplyIndex<std::tuple_size_v<Tuple>>([](auto... I) {
      constexpr auto is_const = [](auto I2) {
        return std::is_const_v<
            std::remove_reference_t<std::tuple_element_t<I2, Tuple>>>;
      };
      std::array<int, (!is_const(I) + ... + 0)> res{};
      int pos = 0;
      ((is_const(I) ? I : res[pos++] = I), ...);
      return res;
    });
  }

  std::tuple<InnerDomains...> inner_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_AGGREGATE_OF_IMPL_H_
