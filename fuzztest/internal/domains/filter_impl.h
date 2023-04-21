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

template <typename Predicate, typename InnerDomain>
class FilterImpl : public DomainBase<FilterImpl<Predicate, InnerDomain>,
                                     user_value_t_of<InnerDomain>,
                                     corpus_value_t_of<InnerDomain>> {
 public:
  using typename FilterImpl::DomainBase::corpus_value_t;
  using typename FilterImpl::DomainBase::user_value_t;

  FilterImpl() = default;
  explicit FilterImpl(Predicate predicate, InnerDomain inner)
      : predicate_(std::move(predicate)), inner_(std::move(inner)) {}

  corpus_value_t Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    while (true) {
      auto v = inner_.Init(prng);
      if (RunFilter(v)) return v;
    }
  }

  void Mutate(corpus_value_t& val, absl::BitGenRef prng, bool only_shrink) {
    corpus_value_t original_val = val;
    while (true) {
      inner_.Mutate(val, prng, only_shrink);
      if (RunFilter(val)) return;
      val = original_val;
    }
  }

  user_value_t CorpusToUserValue(const corpus_value_t& v) const {
    return inner_.CorpusToUserValue(v);
  }

  std::optional<corpus_value_t> UserToCorpusValue(const user_value_t& v) const {
    if (!predicate_(v)) return std::nullopt;
    return inner_.UserToCorpusValue(v);
  }

  auto GetPrinter() const { return inner_.GetPrinter(); }

  std::optional<corpus_value_t> IrToCorpusValue(const IrValue& ir) const {
    return inner_.IrToCorpusValue(ir);
  }

  IrValue CorpusToIrValue(const corpus_value_t& v) const {
    return inner_.CorpusToIrValue(v);
  }

  bool ValidateCorpusValue(const corpus_value_t& corpus_value) const {
    return predicate_(CorpusToUserValue(corpus_value));
  }

 private:
  bool RunFilter(const corpus_value_t& v) {
    ++num_values_;
    bool res = predicate_(CorpusToUserValue(v));
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

  Predicate predicate_;
  InnerDomain inner_;
  uint64_t num_values_ = 0;
  uint64_t num_skips_ = 0;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_FILTER_IMPL_H_
