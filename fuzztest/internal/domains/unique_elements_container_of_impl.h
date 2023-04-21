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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_UNIQUE_ELEMENTS_CONTAINER_OF_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_UNIQUE_ELEMENTS_CONTAINER_OF_IMPL_H_

#include <cstddef>
#include <optional>

#include "absl/container/flat_hash_set.h"
#include "absl/random/bit_gen_ref.h"
#include "./fuzztest/internal/domains/container_of_impl.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/serialization.h"

namespace fuzztest::internal {

template <typename InnerDomain>
using UniqueDomainValueT = absl::flat_hash_set<user_value_t_of<InnerDomain>>;

template <typename InnerDomain>
using UniqueDomain =
    AssociativeContainerOfImpl<UniqueDomainValueT<InnerDomain>, InnerDomain>;

// UniqueElementsContainerImpl supports producing containers of type
// `ContainerT`, with elements of type `ElemenT` from domain `InnerDomain
// inner`, with a guarantee that each element of the container has a unique
// value from `InnerDomain`. The guarantee is provided by using a
// `absl::flat_hash_set<ElementT>` as our corpus_value_t, which is (effectively)
// produced by `UnorderedSetOf(inner)`.
template <typename ContainerT, typename InnerDomain>
class UniqueElementsContainerImpl
    : public DomainBase<UniqueElementsContainerImpl<ContainerT, InnerDomain>,
                        /*UserValueT=*/ContainerT,
                        corpus_value_t_of<UniqueDomain<InnerDomain>>> {
  using UniqueDomainValueT = UniqueDomainValueT<InnerDomain>;
  using UniqueDomain = UniqueDomain<InnerDomain>;

 public:
  using typename UniqueElementsContainerImpl::DomainBase::corpus_value_t;
  using typename UniqueElementsContainerImpl::DomainBase::user_value_t;

  UniqueElementsContainerImpl() = default;
  explicit UniqueElementsContainerImpl(InnerDomain inner)
      : unique_domain_(std::move(inner)) {}

  // All of these methods delegate at least partially to the unique_domain_
  // member.

  corpus_value_t Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    return unique_domain_.Init(prng);
  }

  void Mutate(corpus_value_t& val, absl::BitGenRef prng, bool only_shrink) {
    unique_domain_.Mutate(val, prng, only_shrink);
  }

  user_value_t CorpusToUserValue(const corpus_value_t& v) const {
    UniqueDomainValueT unique_values = unique_domain_.CorpusToUserValue(v);
    return user_value_t(unique_values.begin(), unique_values.end());
  }

  std::optional<corpus_value_t> UserToCorpusValue(const user_value_t& v) const {
    return unique_domain_.UserToCorpusValue(
        user_value_t_of<UniqueDomain>(v.begin(), v.end()));
  }

  auto GetPrinter() const { return unique_domain_.GetPrinter(); }

  std::optional<corpus_value_t> IrToCorpusValue(const IrValue& ir) const {
    return unique_domain_.IrToCorpusValue(ir);
  }

  IrValue CorpusToIrValue(const corpus_value_t& v) const {
    return unique_domain_.CorpusToIrValue(v);
  }

  bool ValidateCorpusValue(const corpus_value_t& corpus_value) const {
    return unique_domain_.ValidateCorpusValue(corpus_value);
  }

  auto& WithSize(size_t s) { return WithMinSize(s).WithMaxSize(s); }
  auto& WithMinSize(size_t s) {
    unique_domain_.WithMinSize(s);
    return *this;
  }
  auto& WithMaxSize(size_t s) {
    unique_domain_.WithMaxSize(s);
    return *this;
  }

 private:
  UniqueDomain unique_domain_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_UNIQUE_ELEMENTS_CONTAINER_OF_IMPL_H_
