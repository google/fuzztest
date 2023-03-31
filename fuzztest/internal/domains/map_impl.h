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

template <typename Mapper, typename... Inner>
class MapImpl : public DomainBase<MapImpl<Mapper, Inner...>,
                                  std::decay_t<std::invoke_result_t<
                                      Mapper, const value_type_t<Inner>&...>>,
                                  std::tuple<corpus_type_t<Inner>...>> {
 public:
  using typename MapImpl::DomainBase::corpus_type;
  using typename MapImpl::DomainBase::value_type;

  MapImpl() = default;
  explicit MapImpl(Mapper mapper, Inner... inner)
      : mapper_(std::move(mapper)), inner_(std::move(inner)...) {}

  MapImpl(absl::string_view map_function_name, Mapper mapper, Inner... inner)
      : mapper_(std::move(mapper)),
        inner_(std::move(inner)...),
        map_function_name_(map_function_name) {}

  corpus_type Init(absl::BitGenRef prng) {
    return std::apply(
        [&](auto&... inner) { return corpus_type(inner.Init(prng)...); },
        inner_);
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    return ApplyIndex<sizeof...(Inner)>([&](auto... I) {
      (std::get<I>(inner_).Mutate(std::get<I>(val), prng, only_shrink), ...);
    });
  }

  value_type GetValue(const corpus_type& v) const {
    return ApplyIndex<sizeof...(Inner)>([&](auto... I) {
      return mapper_(std::get<I>(inner_).GetValue(std::get<I>(v))...);
    });
  }

  std::optional<corpus_type> FromValue(const value_type&) const {
    return std::nullopt;
  }

  auto GetPrinter() const {
    return MappedPrinter<Mapper, Inner...>{mapper_, inner_, map_function_name_};
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    return ParseWithDomainTuple(inner_, obj);
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return SerializeWithDomainTuple(inner_, v);
  }

 private:
  Mapper mapper_;
  std::tuple<Inner...> inner_;
  absl::string_view map_function_name_;
};

template <int&... ExplicitArgumentBarrier, typename Mapper, typename... Inner>
auto NamedMap(absl::string_view name, Mapper mapper, Inner... inner) {
  return internal::MapImpl<Mapper, Inner...>(name, std::move(mapper),
                                             std::move(inner)...);
}

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_MAP_IMPL_H_
