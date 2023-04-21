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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_MAP_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_MAP_IMPL_H_

#include <optional>
#include <tuple>
#include <type_traits>

#include "absl/random/bit_gen_ref.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/domains/serialization_helpers.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

template <typename Mapper, typename... InnerDomains>
class MapImpl
    : public DomainBase<MapImpl<Mapper, InnerDomains...>,
                        /*UserValueT=*/
                        std::decay_t<std::invoke_result_t<
                            Mapper, const user_value_t_of<InnerDomains>&...>>,
                        /*CorpusValueT=*/
                        std::tuple<corpus_value_t_of<InnerDomains>...>> {
 public:
  using typename MapImpl::DomainBase::corpus_value_t;
  using typename MapImpl::DomainBase::user_value_t;

  MapImpl() = default;
  explicit MapImpl(Mapper mapper, InnerDomains... inner)
      : mapper_(std::move(mapper)), inner_(std::move(inner)...) {}

  MapImpl(absl::string_view map_function_name, Mapper mapper,
          InnerDomains... inner)
      : mapper_(std::move(mapper)),
        inner_(std::move(inner)...),
        map_function_name_(map_function_name) {}

  corpus_value_t Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    return std::apply(
        [&](auto&... inner) { return corpus_value_t(inner.Init(prng)...); },
        inner_);
  }

  void Mutate(corpus_value_t& val, absl::BitGenRef prng, bool only_shrink) {
    return ApplyIndex<sizeof...(InnerDomains)>([&](auto... I) {
      (std::get<I>(inner_).Mutate(std::get<I>(val), prng, only_shrink), ...);
    });
  }

  user_value_t CorpusToUserValue(const corpus_value_t& v) const {
    return ApplyIndex<sizeof...(InnerDomains)>([&](auto... I) {
      return mapper_(std::get<I>(inner_).CorpusToUserValue(std::get<I>(v))...);
    });
  }

  std::optional<corpus_value_t> UserToCorpusValue(const user_value_t&) const {
    return std::nullopt;
  }

  auto GetPrinter() const {
    return MappedPrinter<Mapper, InnerDomains...>{mapper_, inner_,
                                                  map_function_name_};
  }

  std::optional<corpus_value_t> IrToCorpusValue(const IrValue& ir) const {
    return ParseWithDomainTuple(inner_, ir);
  }

  IrValue CorpusToIrValue(const corpus_value_t& v) const {
    return SerializeWithDomainTuple(inner_, v);
  }

  bool ValidateCorpusValue(const corpus_value_t& corpus_value) const {
    return ApplyIndex<sizeof...(InnerDomains)>([&](auto... I) {
      return (
          std::get<I>(inner_).ValidateCorpusValue(std::get<I>(corpus_value)) &&
          ...);
    });
  }

 private:
  Mapper mapper_;
  std::tuple<InnerDomains...> inner_;
  absl::string_view map_function_name_;
};

template <int&... ExplicitArgumentBarrier, typename Mapper, typename... Inner>
auto NamedMap(absl::string_view name, Mapper mapper, Inner... inner) {
  return internal::MapImpl<Mapper, Inner...>(name, std::move(mapper),
                                             std::move(inner)...);
}

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_MAP_IMPL_H_
