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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_OPTIONAL_OF_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_OPTIONAL_OF_IMPL_H_

#include <cstdint>
#include <optional>
#include <utility>
#include <variant>

#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/serialization_helpers.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

enum class OptionalPolicy { kWithNull, kWithoutNull, kAlwaysNull };

template <typename T, typename InnerDomain>
class OptionalOfImpl
    : public DomainBase<
          OptionalOfImpl<T, InnerDomain>, T,
          // `T` might be a custom optional type.
          // We use std::variant unconditionally to make it simpler.
          std::variant<std::monostate, corpus_type_t<InnerDomain>>> {
 public:
  using typename OptionalOfImpl::DomainBase::corpus_type;
  using typename OptionalOfImpl::DomainBase::value_type;

  static_assert(Requires<T>([](auto x) -> decltype(!x, *x) {}),
                "T must be an optional type.");

  explicit OptionalOfImpl(InnerDomain inner)
      : inner_(std::move(inner)), policy_(OptionalPolicy::kWithNull) {}

  corpus_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    if (policy_ == OptionalPolicy::kAlwaysNull ||
        // 1/2 chance of returning an empty to avoid initialization with large
        // entities for recursive data structures. See
        // ContainerOfImplBase::ChooseRandomSize for more details.
        (policy_ == OptionalPolicy::kWithNull && absl::Bernoulli(prng, 0.5))) {
      return corpus_type(std::in_place_index<0>);
    } else {
      return corpus_type(std::in_place_index<1>, inner_.Init(prng));
    }
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    if (policy_ == OptionalPolicy::kAlwaysNull) {
      val.template emplace<0>();
      return;
    }
    const bool has_value = val.index() == 1;
    if (!has_value) {
      // Only add a value if we are not shrinking.
      if (!only_shrink) val.template emplace<1>(inner_.Init(prng));
    } else if (policy_ == OptionalPolicy::kWithNull &&
               absl::Bernoulli(prng, 1. / 100)) {
      // 1/100 chance of returning an empty.
      val.template emplace<0>();
    } else {
      inner_.Mutate(std::get<1>(val), prng, only_shrink);
    }
  }

  auto GetPrinter() const {
    return OptionalPrinter<OptionalOfImpl, InnerDomain>{*this, inner_};
  }

  value_type GetValue(const corpus_type& v) const {
    if (v.index() == 0) {
      FUZZTEST_INTERNAL_CHECK(policy_ != OptionalPolicy::kWithoutNull,
                              "Value cannot be null!");
      return value_type();
    }
    FUZZTEST_INTERNAL_CHECK(policy_ != OptionalPolicy::kAlwaysNull,
                            "Value cannot be non-null!");
    return value_type(inner_.GetValue(std::get<1>(v)));
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    if (!v) {
      FUZZTEST_INTERNAL_CHECK(policy_ != OptionalPolicy::kWithoutNull,
                              "Value cannot be null!");
      return corpus_type(std::in_place_index<0>);
    }
    FUZZTEST_INTERNAL_CHECK(policy_ != OptionalPolicy::kAlwaysNull,
                            "Value cannot be non-null!");
    if (auto inner_value = inner_.FromValue(*v)) {
      return corpus_type(std::in_place_index<1>, *std::move(inner_value));
    } else {
      return std::nullopt;
    }
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    std::optional<corpus_type> result = ParseWithDomainOptional(inner_, obj);
    if (!result.has_value()) {
      return std::nullopt;
    }
    bool is_null = std::get_if<std::monostate>(&(*result));
    if ((is_null && policy_ == OptionalPolicy::kWithoutNull) ||
        (!is_null && policy_ == OptionalPolicy::kAlwaysNull)) {
      return std::nullopt;
    }
    return result;
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return SerializeWithDomainOptional(inner_, v);
  }

  OptionalOfImpl& SetAlwaysNull() {
    policy_ = OptionalPolicy::kAlwaysNull;
    return *this;
  }
  OptionalOfImpl& SetWithoutNull() {
    policy_ = OptionalPolicy::kWithoutNull;
    return *this;
  }

  uint64_t CountNumberOfFields(const corpus_type& val) {
    if (val.index() == 1) {
      return inner_.CountNumberOfFields(std::get<1>(val));
    }
    return 0;
  }

  uint64_t MutateSelectedField(corpus_type& val, absl::BitGenRef prng,
                               bool only_shrink,
                               uint64_t selected_field_index) {
    if (val.index() == 1) {
      return inner_.MutateSelectedField(std::get<1>(val), prng, only_shrink,
                                        selected_field_index);
    }
    return 0;
  }

  InnerDomain Inner() const { return inner_; }

 private:
  InnerDomain inner_;
  OptionalPolicy policy_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_OPTIONAL_OF_IMPL_H_
