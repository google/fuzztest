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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ONE_OF_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ONE_OF_IMPL_H_

#include <cstddef>
#include <optional>
#include <tuple>
#include <type_traits>
#include <variant>

#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/serialization_helpers.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

template <typename... InnerDomains>
class OneOfImpl
    : public DomainBase<
          OneOfImpl<InnerDomains...>,
          user_value_t_of<std::tuple_element_t<0, std::tuple<InnerDomains...>>>,
          /*CorpusValueT=*/
          std::variant<corpus_value_t_of<InnerDomains>...>> {
 public:
  using typename OneOfImpl::DomainBase::corpus_value_t;
  using typename OneOfImpl::DomainBase::user_value_t;

  // All user_value_ts of inner domains must be the same. (Though note that they
  // can have different corpus_value_ts!)
  static_assert(
      std::conjunction_v<
          std::is_same<user_value_t, user_value_t_of<InnerDomains>>...>,
      "All domains in a OneOf must have the same user_value_t.");

  explicit OneOfImpl(InnerDomains... domains)
      : domains_(std::move(domains)...) {}

  corpus_value_t Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    // TODO(b/191368509): Consider the cardinality of the subdomains to weight
    // them.
    return Switch<kNumDomains>(
        absl::Uniform(prng, size_t{}, kNumDomains), [&](auto I) {
          return corpus_value_t(std::in_place_index<I>,
                                std::get<I>(domains_).Init(prng));
        });
  }

  void Mutate(corpus_value_t& val, absl::BitGenRef prng, bool only_shrink) {
    // Switch to another domain 1% of the time when not reducing.
    if (kNumDomains > 1 && !only_shrink && absl::Bernoulli(prng, 0.01)) {
      // Choose a different index.
      size_t offset = absl::Uniform<size_t>(prng, 1, kNumDomains);
      size_t index = static_cast<size_t>(val.index());
      index += offset;
      if (index >= kNumDomains) index -= kNumDomains;
      Switch<kNumDomains>(index, [&](auto I) {
        auto& domain = std::get<I>(domains_);
        val.template emplace<I>(domain.Init(prng));
      });
    } else {
      Switch<kNumDomains>(val.index(), [&](auto I) {
        auto& domain = std::get<I>(domains_);
        domain.Mutate(std::get<I>(val), prng, only_shrink);
      });
    }
  }

  user_value_t CorpusToUserValue(const corpus_value_t& v) const {
    return Switch<kNumDomains>(v.index(), [&](auto I) -> user_value_t {
      auto domain = std::get<I>(domains_);
      return domain.CorpusToUserValue(std::get<I>(v));
    });
  }

  std::optional<corpus_value_t> UserToCorpusValue(const user_value_t& v) const {
    std::optional<corpus_value_t> res;
    const auto try_one_corpus = [&](auto I) {
      if (auto inner_res = std::get<I>(domains_).UserToCorpusValue(v)) {
        res.emplace(std::in_place_index<I>, *std::move(inner_res));
        return true;
      }
      return false;
    };

    ApplyIndex<kNumDomains>([&](auto... I) {
      // Try them in order, break on first success.
      (try_one_corpus(I) || ...);
    });

    return res;
  }

  auto GetPrinter() const { return OneOfPrinter<InnerDomains...>{domains_}; }

  std::optional<corpus_value_t> IrToCorpusValue(const IrValue& ir) const {
    return ParseWithDomainVariant(domains_, ir);
  }

  IrValue CorpusToIrValue(const corpus_value_t& v) const {
    return SerializeWithDomainVariant(domains_, v);
  }

  bool ValidateCorpusValue(const corpus_value_t& corpus_value) const {
    return Switch<kNumDomains>(corpus_value.index(), [&](auto I) {
      return std::get<I>(domains_).ValidateCorpusValue(
          std::get<I>(corpus_value));
    });
  }

 private:
  static constexpr size_t kNumDomains = sizeof...(InnerDomains);
  static_assert(kNumDomains > 0, "OneOf requires a non-empty list.");

  std::tuple<InnerDomains...> domains_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ONE_OF_IMPL_H_
