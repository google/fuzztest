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

#include <functional>
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
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
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

  bool ValidateCorpusValue(const corpus_type& corpus_value) const {
    return ApplyIndex<sizeof...(Inner)>([&](auto... I) {
      return (
          std::get<I>(inner_).ValidateCorpusValue(std::get<I>(corpus_value)) &&
          ...);
    });
  }

 private:
  Mapper mapper_;
  std::tuple<Inner...> inner_;
  absl::string_view map_function_name_;
};

template <typename Mapper, typename InvMapper, typename... Inner>
class BidiMapImpl
    : public DomainBase<BidiMapImpl<Mapper, InvMapper, Inner...>,
                        std::decay_t<std::invoke_result_t<
                            Mapper, const value_type_t<Inner>&...>>,
                        std::tuple<corpus_type_t<Inner>...>> {
 public:
  using typename BidiMapImpl::DomainBase::corpus_type;
  using typename BidiMapImpl::DomainBase::value_type;

  static_assert(
      std::is_invocable_v<InvMapper, const value_type&> &&
      std::is_same_v<std::invoke_result_t<InvMapper, const value_type&>,
                     std::tuple<value_type_t<Inner>...>>);

  explicit BidiMapImpl(Mapper mapper, InvMapper inv_mapper, Inner... inner)
      : mapper_(std::move(mapper)),
        inv_mapper_(std::move(inv_mapper)),
        inner_(std::move(inner)...) {}

  corpus_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
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

  auto GetPrinter() const {
    return MappedPrinter<Mapper, Inner...>{mapper_, inner_};
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    return ParseWithDomainTuple(inner_, obj);
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return SerializeWithDomainTuple(inner_, v);
  }

  bool ValidateCorpusValue(const corpus_type& corpus_value) const {
    return ApplyIndex<sizeof...(Inner)>([&](auto... I) {
      return (
          std::get<I>(inner_).ValidateCorpusValue(std::get<I>(corpus_value)) &&
          ...);
    });
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    auto inner_v = std::invoke(inv_mapper_, v);
    return ApplyIndex<sizeof...(Inner)>(
        [&](auto... I) -> std::optional<corpus_type> {
          auto inner_corpus_vals = std::tuple{
              std::get<I>(inner_).FromValue(std::get<I>(inner_v))...};
          bool has_nullopt =
              (!std::get<I>(inner_corpus_vals).has_value() || ...);
          if (has_nullopt) return std::nullopt;
          return std::tuple{*std::move(std::get<I>(inner_corpus_vals))...};
        });
  }

 private:
  Mapper mapper_;
  InvMapper inv_mapper_;
  std::tuple<Inner...> inner_;
};

template <int&... ExplicitArgumentBarrier, typename Mapper, typename InvMapper,
          typename... Inner>
auto BidiMap(Mapper mapper, InvMapper inv_mapper, Inner... inner) {
  return BidiMapImpl<Mapper, InvMapper, Inner...>(
      std::move(mapper), std::move(inv_mapper), std::move(inner)...);
}

template <int&... ExplicitArgumentBarrier, typename Mapper, typename... Inner>
auto NamedMap(absl::string_view name, Mapper mapper, Inner... inner) {
  return internal::MapImpl<Mapper, Inner...>(name, std::move(mapper),
                                             std::move(inner)...);
}

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_MAP_IMPL_H_
