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

template <typename T, typename Inner,
          // We use the type erased version here to allow for recursion in smart
          // pointer domains. It helps cut the recursion in type traits (like
          // corpus_type) and the indirection avoids having the domain contain
          // itself by value.
          typename RealInner = Domain<typename T::element_type>>
class SmartPointerOfImpl
    : public DomainBase<
          SmartPointerOfImpl<T, Inner>, T,
          std::variant<std::monostate, corpus_type_t<RealInner>>> {
  using InnerFn = const RealInner& (*)();

 public:
  using typename SmartPointerOfImpl::DomainBase::corpus_type;
  using typename SmartPointerOfImpl::DomainBase::value_type;

  // Since we allow for recursion in this domain, we want to delay the
  // construction of the inner domain. Otherwise we would have an infinite
  // recursion of domains being created.
  explicit SmartPointerOfImpl(InnerFn fn) : inner_(fn) {}
  explicit SmartPointerOfImpl(Inner inner) : inner_(std::move(inner)) {}

  corpus_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    // Init will always have an empty smart pointer to reduce nesting.
    // Otherwise it is very easy to get a stack overflow during Init() when
    // there is recursion in the domains.
    return corpus_type();
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
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
    return OptionalPrinter<SmartPointerOfImpl, RealInner>{
        *this, GetOrMakeInnerConst()};
  }

  value_type GetValue(const corpus_type& v) const {
    if (v.index() == 0) return value_type();
    return value_type(new auto(GetOrMakeInnerConst().GetValue(std::get<1>(v))));
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    if (!v) return corpus_type(std::in_place_index<0>);
    if (auto inner_value = GetOrMakeInnerConst().FromValue(*v)) {
      return corpus_type(std::in_place_index<1>, *std::move(inner_value));
    } else {
      return std::nullopt;
    }
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    return ParseWithDomainOptional(GetOrMakeInnerConst(), obj);
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return SerializeWithDomainOptional(GetOrMakeInnerConst(), v);
  }

 private:
  RealInner& GetOrMakeInner() {
    if (inner_.index() == 0) {
      inner_.template emplace<1>(std::get<0>(inner_)());
    }
    return std::get<1>(inner_);
  }

  const RealInner& GetOrMakeInnerConst() const {
    return inner_.index() == 0 ? std::get<0>(inner_)() : std::get<1>(inner_);
  }

  // We don't construct it eagerly to avoid an infinite recursion during
  // default construction. We only construct the sub domain on demand.
  std::variant<InnerFn, RealInner> inner_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_SMART_POINTER_OF_IMPL_H_
