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

template <typename UserValueT, typename InnerDomain>
class OptionalOfImpl
    : public DomainBase<
          OptionalOfImpl<UserValueT, InnerDomain>, UserValueT,
          // `T` might be a custom optional type.
          // We use std::variant unconditionally to make it simpler.
          /*CorpusValueT=*/
          std::variant<std::monostate, corpus_value_t_of<InnerDomain>>> {
 public:
  using typename OptionalOfImpl::DomainBase::corpus_value_t;
  using typename OptionalOfImpl::DomainBase::user_value_t;

  static_assert(Requires<UserValueT>([](auto x) -> decltype(!x, *x) {}),
                "T must be an optional type.");

  explicit OptionalOfImpl(InnerDomain inner)
      : inner_(std::move(inner)), policy_(OptionalPolicy::kWithNull) {}

  corpus_value_t Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    if (policy_ == OptionalPolicy::kAlwaysNull ||
        // 1/2 chance of returning an empty to avoid initialization with large
        // entities for recursive data structures. See
        // ContainerOfImplBase::ChooseRandomSize for more details.
        (policy_ == OptionalPolicy::kWithNull && absl::Bernoulli(prng, 0.5))) {
      return corpus_value_t(std::in_place_index<0>);
    } else {
      return corpus_value_t(std::in_place_index<1>, inner_.Init(prng));
    }
  }

  void Mutate(corpus_value_t& val, absl::BitGenRef prng, bool only_shrink) {
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

  user_value_t CorpusToUserValue(const corpus_value_t& v) const {
    if (v.index() == 0) {
      FUZZTEST_INTERNAL_CHECK(policy_ != OptionalPolicy::kWithoutNull,
                              "Value cannot be null!");
      return user_value_t();
    }
    FUZZTEST_INTERNAL_CHECK(policy_ != OptionalPolicy::kAlwaysNull,
                            "Value cannot be non-null!");
    return user_value_t(inner_.CorpusToUserValue(std::get<1>(v)));
  }

  std::optional<corpus_value_t> UserToCorpusValue(const user_value_t& v) const {
    if (!v) {
      FUZZTEST_INTERNAL_CHECK(policy_ != OptionalPolicy::kWithoutNull,
                              "Value cannot be null!");
      return corpus_value_t(std::in_place_index<0>);
    }
    FUZZTEST_INTERNAL_CHECK(policy_ != OptionalPolicy::kAlwaysNull,
                            "Value cannot be non-null!");
    if (auto inner_value = inner_.UserToCorpusValue(*v)) {
      return corpus_value_t(std::in_place_index<1>, *std::move(inner_value));
    } else {
      return std::nullopt;
    }
  }

  std::optional<corpus_value_t> IrToCorpusValue(const IrValue& ir) const {
    return ParseWithDomainOptional(inner_, ir);
  }

  IrValue CorpusToIrValue(const corpus_value_t& v) const {
    return SerializeWithDomainOptional(inner_, v);
  }

  bool ValidateCorpusValue(const corpus_value_t& corpus_value) const {
    bool is_null = std::get_if<std::monostate>(&corpus_value);
    if (is_null) {
      return policy_ != OptionalPolicy::kWithoutNull;
    } else {
      if (policy_ == OptionalPolicy::kAlwaysNull) return false;
      // Validate inner object.
      return inner_.ValidateCorpusValue(std::get<1>(corpus_value));
    }
  }

  OptionalOfImpl& SetAlwaysNull() {
    policy_ = OptionalPolicy::kAlwaysNull;
    return *this;
  }
  OptionalOfImpl& SetWithoutNull() {
    policy_ = OptionalPolicy::kWithoutNull;
    return *this;
  }

  uint64_t CountNumberOfFields(const corpus_value_t& val) {
    if (val.index() == 1) {
      return inner_.CountNumberOfFields(std::get<1>(val));
    }
    return 0;
  }

  uint64_t MutateSelectedField(corpus_value_t& val, absl::BitGenRef prng,
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
