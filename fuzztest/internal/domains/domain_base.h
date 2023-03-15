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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_DOMAIN_BASE_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_DOMAIN_BASE_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <type_traits>

#include "absl/random/bit_gen_ref.h"
#include "absl/strings/str_format.h"
#include "./fuzztest/internal/any.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest {
template <typename>
class Domain;
}  // namespace fuzztest

namespace fuzztest::internal {

// We use this to get a nice compiler error when `T` and `U` don't match instead
// of just "false".
template <typename T, typename U>
constexpr void CheckIsSame() {
  static_assert(std::is_same_v<std::remove_const_t<T>, std::remove_const_t<U>>);
}

// Corpus value type used by Domain<T> template, regardless of T.
using GenericDomainCorpusType = CopyableAny;

// Base class for all domains.
//
// It is "untyped" in that it erases all value_type/corpus_type inputs and
// outputs. This allows code sharing of the runtime.
// All the `Untyped[Name]` functions implement the same API as the `[Name]`
// function but marshalls the inputs and output through the generic types.
class UntypedDomainInterface {
 public:
  virtual ~UntypedDomainInterface() {}

  virtual std::unique_ptr<UntypedDomainInterface> Clone() const = 0;
  virtual GenericDomainCorpusType UntypedInit(absl::BitGenRef) = 0;
  virtual void UntypedMutate(GenericDomainCorpusType& val, absl::BitGenRef prng,
                             bool only_shrink) = 0;
  virtual void UntypedUpdateMemoryDictionary(
      const GenericDomainCorpusType& val) = 0;
  virtual std::optional<GenericDomainCorpusType> UntypedParseCorpus(
      const IRObject& obj) const = 0;
  virtual IRObject UntypedSerializeCorpus(
      const GenericDomainCorpusType& v) const = 0;
  virtual uint64_t UntypedCountNumberOfFields(
      const GenericDomainCorpusType&) = 0;
  virtual uint64_t UntypedMutateSelectedField(GenericDomainCorpusType&,
                                              absl::BitGenRef, bool,
                                              uint64_t) = 0;
  virtual MoveOnlyAny UntypedGetValue(
      const GenericDomainCorpusType& v) const = 0;
  // UntypedPrintCorpusValue is special in that it has an extra parameter
  // `tuple_elem`. This is used to instruct the `std::tuple` domain to print one
  // particular element instead of the whole tuple. This is what the runtime
  // uses to print out the arguments when a counterexample is found.
  // In the `std::tuple` case, it also returns the number of elements in the
  // tuple.
  virtual int UntypedPrintCorpusValue(
      const GenericDomainCorpusType& val, absl::FormatRawSink out,
      internal::PrintMode mode,
      std::optional<int> tuple_elem = std::nullopt) const = 0;
};

// A typed subinterface that provides the methods to handle `value_type`
// inputs/outputs. Some callers require the actual `value_type`.
template <typename ValueType>
class TypedDomainInterface : public UntypedDomainInterface {
 public:
  virtual ValueType TypedGetValue(const GenericDomainCorpusType& v) const = 0;
  virtual std::optional<GenericDomainCorpusType> TypedFromValue(
      const ValueType& v) const = 0;

  MoveOnlyAny UntypedGetValue(const GenericDomainCorpusType& v) const final {
    return MoveOnlyAny(std::in_place_type<ValueType>, TypedGetValue(v));
  }
};

template <typename Derived,
          typename ValueType = ExtractTemplateParameter<0, Derived>>
class DomainBase : public TypedDomainInterface<ValueType> {
 public:
  DomainBase() {
    // Check that the interface of `Derived` matches the requirements for a
    // domain implementation. We check these inside the constructor of
    // `DomainBase`, where `Derived` is already fully defined. If we try to
    // check them at class scope we would see an incomplete `Derived` class and
    // the checks would not work.

    // Has value_type.
    using CheckValueType = typename Derived::value_type;
    static_assert(std::is_same_v<ValueType, CheckValueType>);
    if constexpr (Derived::has_custom_corpus_type) {
      // The type of values that are mutated and stored internally in the
      // "corpus" may be different from the type of values produced by the
      // domain. For example, the corpus_type of InRegexp is a custom data
      // structure representing a path through a state machine, but the domain
      // produces values of type std::string.
      using CheckCorpusType [[maybe_unused]] = typename Derived::corpus_type;
    } else {
      CheckIsSame<typename Derived::value_type, corpus_type_t<Derived>>();
    }
  }

  std::unique_ptr<UntypedDomainInterface> Clone() const final {
    return std::make_unique<Derived>(derived());
  }

  GenericDomainCorpusType UntypedInit(absl::BitGenRef ref) final {
    return GenericDomainCorpusType(std::in_place_type<corpus_type_t<Derived>>,
                                   derived().Init(ref));
  }

  void UntypedMutate(GenericDomainCorpusType& val, absl::BitGenRef prng,
                     bool only_shrink) final {
    derived().Mutate(val.GetAs<corpus_type_t<Derived>>(), prng, only_shrink);
  }

  void UntypedUpdateMemoryDictionary(const GenericDomainCorpusType& val) final {
    derived().UpdateMemoryDictionary(val.GetAs<corpus_type_t<Derived>>());
  }

  ValueType TypedGetValue(const GenericDomainCorpusType& v) const final {
    return derived().GetValue(v.GetAs<corpus_type_t<Derived>>());
  }

  std::optional<GenericDomainCorpusType> TypedFromValue(
      const ValueType& v) const final {
    if (auto c = derived().FromValue(v)) {
      return GenericDomainCorpusType(std::in_place_type<corpus_type_t<Derived>>,
                                     *std::move(c));
    } else {
      return std::nullopt;
    }
  }

  std::optional<GenericDomainCorpusType> UntypedParseCorpus(
      const IRObject& obj) const final {
    if (auto res = derived().ParseCorpus(obj)) {
      return GenericDomainCorpusType(std::in_place_type<corpus_type_t<Derived>>,
                                     *std::move(res));
    } else {
      return std::nullopt;
    }
  }

  IRObject UntypedSerializeCorpus(
      const GenericDomainCorpusType& v) const final {
    return derived().SerializeCorpus(
        v.template GetAs<corpus_type_t<Derived>>());
  }

  uint64_t UntypedCountNumberOfFields(const GenericDomainCorpusType& v) final {
    return derived().CountNumberOfFields(v.GetAs<corpus_type_t<Derived>>());
  }

  uint64_t UntypedMutateSelectedField(GenericDomainCorpusType& v,
                                      absl::BitGenRef prng, bool only_shrink,
                                      uint64_t selected_field_index) final {
    return derived().MutateSelectedField(v.GetAs<corpus_type_t<Derived>>(),
                                         prng, only_shrink,
                                         selected_field_index);
  }

  int UntypedPrintCorpusValue(const GenericDomainCorpusType& val,
                              absl::FormatRawSink out, internal::PrintMode mode,
                              std::optional<int> tuple_elem) const override {
    FUZZTEST_INTERNAL_CHECK(
        !tuple_elem.has_value(),
        "No tuple element should be specified for this override.");
    internal::PrintValue(derived(), val.GetAs<corpus_type_t<Derived>>(), out,
                         mode);
    return -1;
  }

  // Default GetValue and FromValue functions for !has_custom_corpus_type
  // domains.
  ValueType GetValue(const ValueType& v) const {
    static_assert(!Derived::has_custom_corpus_type);
    return v;
  }
  std::optional<ValueType> FromValue(const ValueType& v) const {
    static_assert(!Derived::has_custom_corpus_type);
    return v;
  }

  template <typename D = Derived>
  std::optional<corpus_type_t<D>> ParseCorpus(const IRObject& obj) const {
    static_assert(!D::has_custom_corpus_type);
    return obj.ToCorpus<corpus_type_t<D>>();
  }

  template <typename D = Derived>
  IRObject SerializeCorpus(const corpus_type_t<D>& v) const {
    static_assert(!D::has_custom_corpus_type);
    return IRObject::FromCorpus(v);
  }

  template <typename D = Derived>
  void UpdateMemoryDictionary(const corpus_type_t<D>& val) {}

  template <typename D = Derived>
  uint64_t CountNumberOfFields(const corpus_type_t<D>&) {
    return 0;
  }

  template <typename D = Derived>
  uint64_t MutateSelectedField(corpus_type_t<D>&, absl::BitGenRef, bool,
                               uint64_t) {
    return 0;
  }

  static constexpr bool has_custom_corpus_type = false;

 private:
  Derived& derived() { return static_cast<Derived&>(*this); }
  const Derived& derived() const { return static_cast<const Derived&>(*this); }
};

}  //  namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_DOMAIN_BASE_H_
