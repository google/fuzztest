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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FILTER_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FILTER_IMPL_H_

#include <cstdint>
#include <optional>

#include "absl/random/bit_gen_ref.h"
#include "absl/strings/str_format.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

template <typename Pred, typename Inner>
class FilterImpl
    : public DomainBase<FilterImpl<Pred, Inner>, value_type_t<Inner>,
                        corpus_type_t<Inner>> {
 public:
  using typename FilterImpl::DomainBase::corpus_type;
  using typename FilterImpl::DomainBase::value_type;

  FilterImpl() = default;
  explicit FilterImpl(Pred predicate, Inner inner)
      : predicate_(std::move(predicate)), inner_(std::move(inner)) {}

  corpus_type Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    while (true) {
      auto v = inner_.Init(prng);
      if (RunFilter(v)) return v;
    }
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    corpus_type original_val = val;
    while (true) {
      inner_.Mutate(val, prng, only_shrink);
      if (RunFilter(val)) return;
      val = original_val;
    }
  }

  value_type GetValue(const corpus_type& v) const { return inner_.GetValue(v); }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    if (!predicate_(v)) return std::nullopt;
    return inner_.FromValue(v);
  }

  auto GetPrinter() const { return inner_.GetPrinter(); }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    auto inner_value = inner_.ParseCorpus(obj);
    if (!inner_value || !predicate_(GetValue(*inner_value)))
      return std::nullopt;
    return inner_value;
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return inner_.SerializeCorpus(v);
  }

 private:
  bool RunFilter(const corpus_type& v) {
    ++num_values_;
    bool res = predicate_(GetValue(v));
    if (!res) {
      ++num_skips_;
      if (num_skips_ > 100 && num_skips_ > .9 * num_values_) {
        AbortInTest(absl::StrFormat(R"(

[!] Ineffective use of Filter() detected!

Filter predicate failed on more than 90%% of the samples.
%d out of %d have failed.

Please use Filter() only to skip unlikely values. To filter out a significant
chunk of the input domain, consider defining a custom domain by construction.
See more details in the User Guide.
)",
                                    num_skips_, num_values_));
      }
    }
    return res;
  }

  Pred predicate_;
  Inner inner_;
  uint64_t num_values_ = 0;
  uint64_t num_skips_ = 0;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FILTER_IMPL_H_
