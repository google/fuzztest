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

// UniqueElementsContainerImpl supports producing containers of type `T`, with
// elements of type `E` from domain `InnerDomain inner`, with a guarantee that
// each element of the container has a unique value from `InnerDomain`. The
// guarantee is provided by using a `absl::flat_hash_set<E>` as our corpus_type,
// which is (effectively) produced by `UnorderedSetOf(inner)`.
template <typename T, typename InnerDomain>
class UniqueElementsContainerImpl
    : public DomainBase<UniqueElementsContainerImpl<T, InnerDomain>> {
  using UniqueDomainValueT =
      absl::flat_hash_set<typename InnerDomain::value_type>;
  using UniqueDomain =
      AssociativeContainerOfImpl<UniqueDomainValueT, InnerDomain>;

 public:
  using value_type = T;
  using corpus_type = typename UniqueDomain::corpus_type;
  static constexpr bool has_custom_corpus_type = true;

  UniqueElementsContainerImpl() = default;
  explicit UniqueElementsContainerImpl(InnerDomain inner)
      : unique_domain_(std::move(inner)) {}

  // All of these methods delegate at least partially to the unique_domain_
  // member.

  corpus_type Init(absl::BitGenRef prng) { return unique_domain_.Init(prng); }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    unique_domain_.Mutate(val, prng, only_shrink);
  }

  value_type GetValue(const corpus_type& v) const {
    UniqueDomainValueT unique_values = unique_domain_.GetValue(v);
    return value_type(unique_values.begin(), unique_values.end());
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    return unique_domain_.FromValue(
        typename UniqueDomain::value_type(v.begin(), v.end()));
  }

  auto GetPrinter() const { return unique_domain_.GetPrinter(); }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    return unique_domain_.ParseCorpus(obj);
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return unique_domain_.SerializeCorpus(v);
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
