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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ELEMENT_OF_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ELEMENT_OF_IMPL_H_

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

enum class ElementOfImplCorpusValueT : size_t;

template <typename UserValueT>
class ElementOfImpl : public DomainBase<ElementOfImpl<UserValueT>, UserValueT,
                                        ElementOfImplCorpusValueT> {
 public:
  using typename ElementOfImpl::DomainBase::corpus_value_t;
  using typename ElementOfImpl::DomainBase::user_value_t;

  explicit ElementOfImpl(std::vector<UserValueT> values) : values_(values) {
    FUZZTEST_INTERNAL_CHECK_PRECONDITION(
        !values.empty(), "ElementOf requires a non empty list.");
  }

  corpus_value_t Init(absl::BitGenRef prng) {
    if (auto seed = this->MaybeGetRandomSeed(prng)) return *seed;
    return corpus_value_t{absl::Uniform<size_t>(prng, 0, values_.size())};
  }

  void Mutate(corpus_value_t& val, absl::BitGenRef prng, bool only_shrink) {
    if (values_.size() <= 1) return;
    if (only_shrink) {
      size_t index = static_cast<size_t>(val);
      if (index == 0) return;
      index = absl::Uniform<size_t>(prng, 0, index);
      val = static_cast<corpus_value_t>(index);
      return;
    }
    // Choose a different index.
    size_t offset = absl::Uniform<size_t>(prng, 1, values_.size());
    size_t index = static_cast<size_t>(val);
    index += offset;
    if (index >= values_.size()) index -= values_.size();
    val = static_cast<corpus_value_t>(index);
  }

  user_value_t CorpusToUserValue(corpus_value_t value) const {
    return values_[static_cast<size_t>(value)];
  }

  std::optional<corpus_value_t> UserToCorpusValue(const user_value_t& v) const {
    // For simple scalar types we try to find them in the list.
    // Otherwise, we fail unconditionally because we might not be able to
    // effectively compare the values.
    // Checking for `operator==` is not enough. You will have false positives
    // where `operator==` exists but it either doens't compile or it gives the
    // wrong answer.
    if constexpr (std::is_enum_v<user_value_t> ||
                  std::is_arithmetic_v<user_value_t> ||
                  std::is_same_v<std::string, user_value_t> ||
                  std::is_same_v<std::string_view, user_value_t>) {
      auto it = std::find(values_.begin(), values_.end(), v);
      return it == values_.end() ? std::nullopt
                                 : std::optional(static_cast<corpus_value_t>(
                                       it - values_.begin()));
    }
    return std::nullopt;
  }

  auto GetPrinter() const { return AutodetectTypePrinter<UserValueT>(); }

  std::optional<corpus_value_t> IrToCorpusValue(const IrValue& ir) const {
    return ir.ToCorpus<corpus_value_t>();
  }

  IrValue CorpusToIrValue(const corpus_value_t& v) const {
    return IrValue::FromCorpus(v);
  }

  bool ValidateCorpusValue(const corpus_value_t& corpus_value) const {
    return static_cast<size_t>(corpus_value) < values_.size();
  }

 private:
  std::vector<UserValueT> values_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ELEMENT_OF_IMPL_H_
