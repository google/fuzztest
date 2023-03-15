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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_CONTAINER_OF_IMPL_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_CONTAINER_OF_IMPL_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <list>
#include <optional>
#include <string>
#include <type_traits>

#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "absl/strings/str_format.h"
#include "absl/types/span.h"
#include "./fuzztest/internal/coverage.h"
#include "./fuzztest/internal/domains/container_mutation_helpers.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/table_of_recent_compares.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

// Used for ChoosePosition();
enum class IncludeEnd { kYes, kNo };

// For cases where the type is a container, choose one of the elements in the
// container.
template <typename Container>
auto ChoosePosition(Container& val, IncludeEnd include_end,
                    absl::BitGenRef prng) {
  size_t i = absl::Uniform<size_t>(
      prng, 0, include_end == IncludeEnd::kYes ? val.size() + 1 : val.size());
  return std::next(val.begin(), i);
}

// Common base for container domains. Provides common APIs.
template <typename Derived>
class ContainerOfImplBase : public DomainBase<Derived> {
  using InnerDomainT = ExtractTemplateParameter<1, Derived>;

 public:
  using value_type = ExtractTemplateParameter<0, Derived>;
  static constexpr bool has_custom_corpus_type =
      // Specialized handling of vector<bool> since you can't actually hold
      // a reference to a single bit but instead get a proxy value.
      is_bitvector_v<value_type> ||
      // If the container is associative we force a custom corpus type to allow
      // modifying the keys.
      is_associative_container_v<value_type> ||
      InnerDomainT::has_custom_corpus_type;
  // `corpus_type` might be immutable (eg std::pair<const int, int> for maps
  // inner domain). We store them in a std::list to allow for this.

  // Some container mutation only applies to vector or string types which do
  // not have a custom corpus type.
  static constexpr bool is_vector_or_string =
      !has_custom_corpus_type &&
      (is_vector_v<value_type> || std::is_same_v<value_type, std::string>);

  // The current implementation of container dictionary only supports
  // vector or string container value_type, whose InnerDomain is
  // an `ArbitraryImpl<T2>` where T2 is an integral type.
  static constexpr bool container_has_memory_dict =
      is_memory_dictionary_compatible<InnerDomainT>::value &&
      is_vector_or_string;

  using corpus_type =
      std::conditional_t<has_custom_corpus_type,
                         std::list<corpus_type_t<InnerDomainT>>, value_type>;

  // If `!container_has_memory_dict`, dict_type is a bool and dict
  // is not used. This conditional_t may be neccessary because some
  // value_type may not have copy constructors(for example, proto).
  // Making it a safe type(bool) to not break some targets.
  using dict_type = std::conditional_t<container_has_memory_dict,
                                       ContainerDictionary<value_type>, bool>;
  using dict_entry_type = std::conditional_t<container_has_memory_dict,
                                             DictionaryEntry<value_type>, bool>;

  ContainerOfImplBase() = default;
  explicit ContainerOfImplBase(InnerDomainT inner) : inner_(std::move(inner)) {}

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    permanent_dict_candidate_ = std::nullopt;
    FUZZTEST_INTERNAL_CHECK(
        val.size() >= this->min_size_ && val.size() <= this->max_size_, "size ",
        val.size(), " is not between [", this->min_size_, "; ", this->max_size_,
        "]");

    const bool can_shrink = val.size() > this->min_size_;
    const bool can_grow = !only_shrink && val.size() < this->max_size_;
    const bool can_change = val.size() != 0;
    const bool can_use_memory_dict = !only_shrink &&
                                     container_has_memory_dict && can_change &&
                                     GetExecutionCoverage() != nullptr;

    const int action_count =
        can_shrink + can_grow + can_change + can_use_memory_dict;
    if (action_count == 0) return;
    int action = absl::Uniform(prng, 0, action_count);

    if (can_shrink) {
      if (action-- == 0) {
        // If !has_custom_corpus_type, try shrink a consecutive chunk
        // or shrink 1 with equal probability.
        // Otherwise always shrink 1.
        if constexpr (!has_custom_corpus_type) {
          if (absl::Bernoulli(prng, 0.5)) {
            EraseRandomChunk(val, prng, this->min_size_);
            return;
          }
        }
        val.erase(ChoosePosition(val, IncludeEnd::kNo, prng));
        return;
      }
    }
    if (can_grow) {
      if (action-- == 0) {
        // If !has_custom_corpus_type, try grow a consecutive chunk or
        // grow 1 with equal probability. Otherwise
        // always grow 1.
        if constexpr (!has_custom_corpus_type) {
          if (absl::Bernoulli(prng, 0.5)) {
            auto element_val = inner_.Init(prng);
            InsertRandomChunk(val, prng, this->max_size_, element_val);
            return;
          }
        }
        Self().GrowOne(val, prng);
        return;
      }
    }
    if (can_change) {
      if (action-- == 0) {
        // If !has_custom_corpus_type, try mutate a consecutive chunk or
        // mutate 1 with equal probability. Otherwise
        // always mutate 1.
        if constexpr (!has_custom_corpus_type) {
          if (absl::Bernoulli(prng, 0.5)) {
            size_t change_offset = ChooseOffset(val.size(), prng);
            size_t changes =
                absl::Uniform(absl::IntervalClosedClosed, prng, size_t{1},
                              std::min(val.size() - change_offset, size_t{15}));
            auto it_start = std::next(val.begin(), change_offset);
            auto it_end = std::next(it_start, changes);
            for (; it_start != it_end; it_start = std::next(it_start)) {
              Self().MutateElement(val, prng, it_start, only_shrink);
            }
            return;
          }
        }
        Self().MutateElement(
            val, prng, ChoosePosition(val, IncludeEnd::kNo, prng), only_shrink);
        return;
      }
    }
    if constexpr (container_has_memory_dict) {
      if (can_use_memory_dict) {
        if (action-- == 0) {
          bool mutated = MemoryDictionaryMutation(
              val, prng, temporary_dict_, manual_dict_, permanent_dict_,
              permanent_dict_candidate_, this->max_size_);
          // If dict failed, fall back to changing an element.
          if (!mutated) {
            Self().MutateElement(val, prng,
                                 ChoosePosition(val, IncludeEnd::kNo, prng),
                                 only_shrink);
          }
          return;
        }
      }
    }
  }

  void UpdateMemoryDictionary(const corpus_type& val) {
    // TODO(JunyangShao): Implement dictionary propagation to container
    // elements. For now the propagation stops in container domains.
    // Because all elements share an `inner_` and will share
    // a dictionary if we propagate it, which makes the dictionary
    // not efficient.
    if constexpr (container_has_memory_dict) {
      if (GetExecutionCoverage() != nullptr) {
        temporary_dict_.MatchEntriesFromTableOfRecentCompares(
            val, GetExecutionCoverage()->GetTablesOfRecentCompares());
        if (permanent_dict_candidate_.has_value() &&
            permanent_dict_.Size() < kPermanentDictMaxSize) {
          permanent_dict_.AddEntry(std::move(*permanent_dict_candidate_));
          permanent_dict_candidate_ = std::nullopt;
        }
      }
    }
  }

  // These are specific for containers only. They are not part of the common
  // Domain API.
  Derived& WithSize(size_t s) { return WithMinSize(s).WithMaxSize(s); }
  Derived& WithMinSize(size_t s) {
    min_size_ = s;
    return static_cast<Derived&>(*this);
  }
  Derived& WithMaxSize(size_t s) {
    max_size_ = s;
    return static_cast<Derived&>(*this);
  }
  Derived& WithDictionary(absl::Span<const value_type> manual_dict) {
    static_assert(container_has_memory_dict,
                  "Manual Dictionary now only supports std::vector or "
                  "std::string or std::string_view.\n");
    for (const value_type& entry : manual_dict) {
      FUZZTEST_INTERNAL_CHECK(
          entry.size() <= this->max_size_,
          "At least one dictionary entry is larger than max container size.");
      manual_dict_.AddEntry({std::nullopt, entry});
    }
    return static_cast<Derived&>(*this);
  }

  auto GetPrinter() const {
    if constexpr (std::is_same_v<value_type, std::string>) {
      // std::string has special handling for better output
      return StringPrinter{};
    } else {
      return ContainerPrinter<Derived, InnerDomainT>{inner_};
    }
  }

  value_type GetValue(const corpus_type& value) const {
    if constexpr (has_custom_corpus_type) {
      value_type result;
      for (const auto& v : value) {
        result.insert(result.end(), inner_.GetValue(v));
      }
      return result;
    } else {
      return value;
    }
  }

  std::optional<corpus_type> FromValue(const value_type& value) const {
    if constexpr (!has_custom_corpus_type) {
      return value;
    } else {
      corpus_type res;
      for (const auto& elem : value) {
        auto inner_value = inner_.FromValue(elem);
        if (!inner_value) return std::nullopt;
        res.push_back(*std::move(inner_value));
      }
      return res;
    }
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    std::optional<corpus_type> res = ParseCorpusWithoutValidation(obj);
    if (res.has_value()) {
      value_type v = GetValue(*res);
      if (v.size() < min_size_ || v.size() > max_size_) {
        return std::nullopt;
      }
    }
    return res;
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    if constexpr (has_custom_corpus_type) {
      IRObject obj;
      auto& subs = obj.MutableSubs();
      for (const auto& elem : v) {
        subs.push_back(inner_.SerializeCorpus(elem));
      }
      return obj;
    } else {
      return IRObject::FromCorpus(v);
    }
  }

  InnerDomainT Inner() const { return inner_; }

  template <typename OtherDerived>
  friend class ContainerOfImplBase;

  template <typename OtherDerived>
  void CopyConstraintsFrom(const ContainerOfImplBase<OtherDerived>& other) {
    min_size_ = other.min_size_;
    max_size_ = other.max_size_;
  }

 protected:
  InnerDomainT inner_;

  int ChooseRandomSize(absl::BitGenRef prng) {
    // The container size should not be empty (unless max_size_ = 0) because the
    // initialization should be random if possible.
    // TODO(changochen): Increase the number of generated elements.
    // Currently we make container generate zero or one element to avoid
    // infinite recursion in recursive data structures. For the example, we want
    // to build a domain for `struct X{ int leaf; vector<X> recursive`, the
    // expected generated length is `E(X) = E(leaf) + E(recursive)`. If the
    // container generate `0-10` elements when calling `Init`, then
    // `E(recursive) =  4.5 E(X)`, which will make `E(X) = Infinite`.
    // Make some smallish random seed containers.
    return absl::Uniform(prng, min_size_,
                         std::min(max_size_ + 1, min_size_ + 2));
  }

  size_t min_size_ = 0;
  size_t max_size_ = 1000;

 private:
  // Use the generic serializer when no custom corpus type is used, since it is
  // more efficient. Eg a string value can be serialized as a string instead of
  // as a sequence of char values.
  std::optional<corpus_type> ParseCorpusWithoutValidation(
      const IRObject& obj) const {
    if constexpr (has_custom_corpus_type) {
      auto subs = obj.Subs();
      if (!subs) return std::nullopt;
      corpus_type res;
      for (const auto& elem : *subs) {
        if (auto parsed_elem = inner_.ParseCorpus(elem)) {
          res.insert(res.end(), std::move(*parsed_elem));
        } else {
          return std::nullopt;
        }
      }
      return res;
    } else {
      return obj.ToCorpus<corpus_type>();
    }
  }

  Derived& Self() { return static_cast<Derived&>(*this); }

  // Temporary memory dictionary. Collected from tracing the program
  // execution. It will always be empty if no execution_coverage_ is found,
  // for example when running with other fuzzer engines.
  dict_type temporary_dict_ = {};

  // Dictionary provided by the user. It has the same type requirements as
  // memory dictionaries, but it could be made more general.
  // TODO(JunyangShao): make it more general.
  dict_type manual_dict_ = {};

  // Permanent memory dictionary. Contains entries upgraded from
  // temporary_dict_. Upgrade happens when a temporary_dict_ entry
  // leads to new coverage.
  dict_type permanent_dict_ = {};
  static constexpr size_t kPermanentDictMaxSize = 512;

  // Keep tracks of what temporary_dict_ entry was used in the last dictionary
  // mutation. Will get upgraded into permanent_dict_ if it leads to new
  // coverages.
  std::optional<dict_entry_type> permanent_dict_candidate_ = std::nullopt;
};

// Base class for associative container domains, such as Domain<std::set> and
// Domain<absl::flat_hash_map>; these container have a key_type, used for
// element access by key.
template <typename T, typename InnerDomain>
class AssociativeContainerOfImpl
    : public ContainerOfImplBase<AssociativeContainerOfImpl<T, InnerDomain>> {
  using Base = typename AssociativeContainerOfImpl::ContainerOfImplBase;

 public:
  using value_type = T;
  using corpus_type = typename Base::corpus_type;
  static constexpr bool has_custom_corpus_type = Base::has_custom_corpus_type;
  static_assert(has_custom_corpus_type, "Must be custom to mutate keys");

  AssociativeContainerOfImpl() = default;
  explicit AssociativeContainerOfImpl(InnerDomain inner)
      : Base(std::move(inner)) {}

  corpus_type Init(absl::BitGenRef prng) {
    const int size = this->ChooseRandomSize(prng);

    corpus_type val;
    Grow(val, prng, size, 10000);
    if (val.size() < this->min_size_) {
      // We tried to make a container with the minimum specified size and we
      // could not after a lot of attempts. This could be caused by an
      // unsatisfiable domain, such as one where the minimum desired size is
      // greater than the number of unique `value_type` values that exist; for
      // example, a uint8_t has only 256 possible values, so we can't create
      // a std::set<uint8_t> whose size is greater than 256, as requested here:
      //
      //    SetOf(Arbitrary<uint8_t>()).WithMinSize(300)
      //
      // Abort the test and inform the user.
      AbortInTest(absl::StrFormat(R"(

[!] Ineffective use of WithSize()/WithMinSize() detected!

The domain failed trying to find enough values that satisfy the constraints.
The minimum size requested is %u and we could only find %u elements.

Please verify that the inner domain can provide enough values.
)",
                                  this->min_size_, val.size()));
    }
    return val;
  }

 private:
  friend Base;

  void GrowOne(corpus_type& val, absl::BitGenRef prng) {
    constexpr size_t kFailuresAllowed = 100;
    Grow(val, prng, 1, kFailuresAllowed);
  }

  // Try to grow `val` by `n` elements.
  void Grow(corpus_type& val, absl::BitGenRef prng, size_t n,
            size_t failures_allowed) {
    // Try a few times to insert a new element (correctly assuming the
    // initialization yields a random element if possible). We might get
    // duplicates. But don't try forever because we might be at the limit of the
    // container. Eg a set<char> with 256 elements can't grow anymore.
    //
    // Use the real value to make sure we are not adding invalid elements to the
    // list. The insertion in `real_value` will do the deduping for us.
    auto real_value = this->GetValue(val);
    const size_t final_size = real_value.size() + n;
    while (real_value.size() < final_size) {
      auto new_element = this->inner_.Init(prng);
      if (real_value.insert(this->inner_.GetValue(new_element)).second) {
        val.push_back(std::move(new_element));
      } else {
        // Just stop if we reached the allowed failures.
        // Let the caller decide what to do.
        if (failures_allowed-- == 0) return;
      }
    }
  }

  // Try to mutate the element in `it`.
  void MutateElement(corpus_type& val, absl::BitGenRef prng,
                     typename corpus_type::iterator it, bool only_shrink) {
    size_t failures_allowed = 100;
    // Try a few times to mutate the element.
    // If the mutation reduces the number of elements in the container it means
    // we made the key collide with an existing element. Don't try forever as
    // there might not be any other value that we can mutate to.
    // Eg a set<char> with 256 elements can't mutate any of its elements.
    //
    // Use the real value to make sure we are not adding invalid elements to the
    // list. The insertion in `real_value` will do the deduping for us.
    corpus_type original_element_list;
    original_element_list.splice(original_element_list.end(), val, it);
    auto real_value = this->GetValue(val);

    while (failures_allowed > 0) {
      auto new_element = original_element_list.front();
      this->inner_.Mutate(new_element, prng, only_shrink);
      if (real_value.insert(this->inner_.GetValue(new_element)).second) {
        val.push_back(std::move(new_element));
        return;
      } else {
        --failures_allowed;
      }
    }
    // Give up and put the element back.
    val.splice(val.end(), original_element_list);
  }
};

template <typename T, typename InnerDomain>
class SequenceContainerOfImpl
    : public ContainerOfImplBase<SequenceContainerOfImpl<T, InnerDomain>> {
  using Base = typename SequenceContainerOfImpl::ContainerOfImplBase;

 public:
  using value_type = T;
  using corpus_type = typename Base::corpus_type;

  SequenceContainerOfImpl() = default;
  explicit SequenceContainerOfImpl(InnerDomain inner)
      : Base(std::move(inner)) {}

  corpus_type Init(absl::BitGenRef prng) {
    const int size = this->ChooseRandomSize(prng);
    corpus_type val;
    while (val.size() < size) {
      val.insert(val.end(), this->inner_.Init(prng));
    }
    return val;
  }

  uint64_t CountNumberOfFields(const corpus_type& val) {
    uint64_t total_weight = 0;
    for (auto& i : val) {
      total_weight += this->inner_.CountNumberOfFields(i);
    }
    return total_weight;
  }

  uint64_t MutateSelectedField(corpus_type& val, absl::BitGenRef prng,
                               bool only_shrink,
                               uint64_t selected_field_index) {
    uint64_t field_counter = 0;
    for (auto& i : val) {
      field_counter += this->inner_.MutateSelectedField(
          i, prng, only_shrink, selected_field_index - field_counter);
      if (field_counter >= selected_field_index) break;
    }
    return field_counter;
  }

 private:
  friend Base;

  void GrowOne(corpus_type& val, absl::BitGenRef prng) {
    val.insert(ChoosePosition(val, IncludeEnd::kYes, prng),
               this->inner_.Init(prng));
  }

  void MutateElement(corpus_type&, absl::BitGenRef prng,
                     typename corpus_type::iterator it, bool only_shrink) {
    this->inner_.Mutate(*it, prng, only_shrink);
  }
};

template <typename T, typename InnerDomain>
using ContainerOfImpl =
    std::conditional_t<is_associative_container_v<T>,
                       AssociativeContainerOfImpl<T, InnerDomain>,
                       SequenceContainerOfImpl<T, InnerDomain>>;

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_CONTAINER_OF_IMPL_H_
