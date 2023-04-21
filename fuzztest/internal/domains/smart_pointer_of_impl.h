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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_SMART_POINTER_OF_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_SMART_POINTER_OF_IMPL_H_

#include <optional>
#include <utility>
#include <variant>

#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/serialization_helpers.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

template <typename UserValueT, typename InnerDomain,
          // We use the type erased version here to allow for recursion in smart
          // pointer domains. It helps cut the recursion in type traits (like
          // corpus_value_t) and the indirection avoids having the domain
          // contain itself by value.
          typename RealInnerDomain = Domain<typename UserValueT::element_type>>
class SmartPointerOfImpl
    : public DomainBase<
          SmartPointerOfImpl<UserValueT, InnerDomain>, UserValueT,
          /*CorpusValueT=*/
          std::variant<std::monostate, corpus_value_t_of<RealInnerDomain>>> {
  using InnerFn = const RealInnerDomain& (*)();

 public:
  using typename SmartPointerOfImpl::DomainBase::corpus_value_t;
  using typename SmartPointerOfImpl::DomainBase::user_value_t;

  // Since we allow for recursion in this domain, we want to delay the
  // construction of the inner domain. Otherwise we would have an infinite
  // recursion of domains being created.
  explicit SmartPointerOfImpl(InnerFn fn) : inner_(fn) {}
  explicit SmartPointerOfImpl(InnerDomain inner) : inner_(std::move(inner)) {}

  corpus_value_t Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    // Init will always have an empty smart pointer to reduce nesting.
    // Otherwise it is very easy to get a stack overflow during Init() when
    // there is recursion in the domains.
    return corpus_value_t();
  }

  void Mutate(corpus_value_t& val, absl::BitGenRef prng, bool only_shrink) {
    const bool has_value = val.index() == 1;
    if (!has_value) {
      // Only add a value if we are not shrinking.
      if (!only_shrink) val.template emplace<1>(GetOrMakeInner().Init(prng));
    } else if (absl::Bernoulli(prng, 1. / 100)) {
      // 1/100 chance of returning an empty.
      val.template emplace<0>();
    } else {
      GetOrMakeInner().Mutate(std::get<1>(val), prng, only_shrink);
    }
  }

  auto GetPrinter() const {
    return OptionalPrinter<SmartPointerOfImpl, RealInnerDomain>{
        *this, GetOrMakeInnerConst()};
  }

  user_value_t CorpusToUserValue(const corpus_value_t& v) const {
    if (v.index() == 0) return user_value_t();
    return user_value_t(
        new auto(GetOrMakeInnerConst().CorpusToUserValue(std::get<1>(v))));
  }

  std::optional<corpus_value_t> UserToCorpusValue(const user_value_t& v) const {
    if (!v) return corpus_value_t(std::in_place_index<0>);
    if (auto inner_value = GetOrMakeInnerConst().UserToCorpusValue(*v)) {
      return corpus_value_t(std::in_place_index<1>, *std::move(inner_value));
    } else {
      return std::nullopt;
    }
  }

  std::optional<corpus_value_t> IrToCorpusValue(const IrValue& ir) const {
    return ParseWithDomainOptional(GetOrMakeInnerConst(), ir);
  }

  IrValue CorpusToIrValue(const corpus_value_t& v) const {
    return SerializeWithDomainOptional(GetOrMakeInnerConst(), v);
  }

  bool ValidateCorpusValue(const corpus_value_t& corpus_value) const {
    return (corpus_value.index() == 0) ||
           GetOrMakeInnerConst().ValidateCorpusValue(std::get<1>(corpus_value));
  }

 private:
  RealInnerDomain& GetOrMakeInner() {
    if (inner_.index() == 0) {
      inner_.template emplace<1>(std::get<0>(inner_)());
    }
    return std::get<1>(inner_);
  }

  const RealInnerDomain& GetOrMakeInnerConst() const {
    return inner_.index() == 0 ? std::get<0>(inner_)() : std::get<1>(inner_);
  }

  // We don't construct it eagerly to avoid an infinite recursion during
  // default construction. We only construct the sub domain on demand.
  std::variant<InnerFn, RealInnerDomain> inner_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_SMART_POINTER_OF_IMPL_H_
