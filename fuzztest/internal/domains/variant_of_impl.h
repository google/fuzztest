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

template <typename UserValueT, typename... InnerDomains>
class VariantOfImpl
    : public DomainBase<VariantOfImpl<UserValueT, InnerDomains...>, UserValueT,
                        // `T` might be a custom variant type.
                        // We use std::variant unconditionally
                        // to make it simpler.
                        /*CorpusValueT=*/
                        std::variant<corpus_value_t_of<InnerDomains>...>> {
 public:
  using typename VariantOfImpl::DomainBase::corpus_value_t;
  using typename VariantOfImpl::DomainBase::user_value_t;

  VariantOfImpl() = default;
  explicit VariantOfImpl(std::in_place_t, InnerDomains... inner_domains)
      : inner_domains_(std::move(inner_domains)...) {}

  corpus_value_t Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    return Switch<sizeof...(InnerDomains)>(
        absl::Uniform(prng, size_t{}, sizeof...(InnerDomains)), [&](auto I) {
          return corpus_value_t(std::in_place_index<I>,
                                std::get<I>(inner_domains_).Init(prng));
        });
  }

  void Mutate(corpus_value_t& val, absl::BitGenRef prng, bool only_shrink) {
    // Flip a coin to choose between generating a value of an alternative type
    // and mutating the value of the current type. Assign more weight to the
    // mutating case in order to explore more on a given type before we start
    // from scratch again.
    if (absl::Bernoulli(prng, 0.2)) {
      val = Init(prng);
    } else {
      Switch<sizeof...(InnerDomains)>(val.index(), [&](auto I) {
        std::get<I>(inner_domains_).Mutate(std::get<I>(val), prng, only_shrink);
      });
    }
  }

  auto GetPrinter() const {
    return VariantPrinter<InnerDomains...>{inner_domains_};
  }

  user_value_t CorpusToUserValue(const corpus_value_t& v) const {
    return Switch<sizeof...(InnerDomains)>(
        v.index(), [&](auto I) -> user_value_t {
          user_value_t out;
          out.template emplace<I>(
              std::get<I>(inner_domains_).CorpusToUserValue(std::get<I>(v)));
          return out;
        });
  }

  std::optional<corpus_value_t> UserToCorpusValue(const user_value_t& v) const {
    return Switch<sizeof...(InnerDomains)>(
        v.index(), [&](auto I) -> std::optional<corpus_value_t> {
          if (auto inner_value = std::get<I>(inner_domains_)
                                     .UserToCorpusValue(std::get<I>(v))) {
            return corpus_value_t(std::in_place_index<I>,
                                  *std::move(inner_value));
          } else {
            return std::nullopt;
          }
        });
  }

  std::optional<corpus_value_t> IrToCorpusValue(const IrValue& ir) const {
    return ParseWithDomainVariant(inner_domains_, ir);
  }

  IrValue CorpusToIrValue(const corpus_value_t& v) const {
    return SerializeWithDomainVariant(inner_domains_, v);
  }

  bool ValidateCorpusValue(const corpus_value_t& corpus_value) const {
    return Switch<sizeof...(InnerDomains)>(corpus_value.index(), [&](auto I) {
      return std::get<I>(inner_domains_)
          .ValidateCorpusValue(std::get<I>(corpus_value));
    });
  }

 private:
  std::tuple<InnerDomains...> inner_domains_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_VARIANT_OF_IMPL_H_
