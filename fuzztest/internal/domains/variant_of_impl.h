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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_VARIANT_OF_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_VARIANT_OF_IMPL_H_

#include <cstddef>
#include <optional>
#include <tuple>
#include <utility>
#include <variant>

#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/serialization_helpers.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

template <typename T, typename... Inner>
class VariantOfImpl : public DomainBase<VariantOfImpl<T, Inner...>, T,
                                        // `T` might be a custom variant type.
                                        // We use std::variant unconditionally
                                        // to make it simpler.
                                        std::variant<corpus_type_t<Inner>...>> {
 public:
  using typename VariantOfImpl::DomainBase::corpus_type;
  using typename VariantOfImpl::DomainBase::value_type;

  VariantOfImpl() = default;
  explicit VariantOfImpl(std::in_place_t, Inner... inner)
      : inner_(std::move(inner)...) {}

  corpus_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    return Switch<sizeof...(Inner)>(
        absl::Uniform(prng, size_t{}, sizeof...(Inner)), [&](auto I) {
          return corpus_type(std::in_place_index<I>,
                             std::get<I>(inner_).Init(prng));
        });
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    // Flip a coin to choose between generating a value of an alternative type
    // and mutating the value of the current type. Assign more weight to the
    // mutating case in order to explore more on a given type before we start
    // from scratch again.
    if (absl::Bernoulli(prng, 0.2)) {
      val = Init(prng);
    } else {
      Switch<sizeof...(Inner)>(val.index(), [&](auto I) {
        std::get<I>(inner_).Mutate(std::get<I>(val), prng, only_shrink);
      });
    }
  }

  auto GetPrinter() const { return VariantPrinter<Inner...>{inner_}; }

  value_type GetValue(const corpus_type& v) const {
    return Switch<sizeof...(Inner)>(v.index(), [&](auto I) -> value_type {
      value_type out;
      out.template emplace<I>(std::get<I>(inner_).GetValue(std::get<I>(v)));
      return out;
    });
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    return Switch<sizeof...(Inner)>(
        v.index(), [&](auto I) -> std::optional<corpus_type> {
          if (auto inner_value =
                  std::get<I>(inner_).FromValue(std::get<I>(v))) {
            return corpus_type(std::in_place_index<I>, *std::move(inner_value));
          } else {
            return std::nullopt;
          }
        });
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    return ParseWithDomainVariant(inner_, obj);
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return SerializeWithDomainVariant(inner_, v);
  }

 private:
  std::tuple<Inner...> inner_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_VARIANT_OF_IMPL_H_
