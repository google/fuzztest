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
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <type_traits>
#include <vector>

#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "./fuzztest/internal/any.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/table_of_recent_compares.h"
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
  static_assert(std::is_same_v<T, U>);
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
  virtual absl::Status UntypedValidateCorpusValue(
      const GenericDomainCorpusType& corpus_value) const = 0;
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
          typename ValueType = ExtractTemplateParameter<0, Derived>,
          typename CorpusType = ValueType>
class DomainBase : public TypedDomainInterface<ValueType> {
 public:
  using value_type = ValueType;
  using corpus_type = CorpusType;
  static constexpr bool has_custom_corpus_type =
      !std::is_same_v<ValueType, CorpusType>;

  DomainBase() {
    // Check that the interface of `Derived` matches the requirements for a
    // domain implementation. We check these inside the constructor of
    // `DomainBase`, where `Derived` is already fully defined. If we try to
    // check them at class scope we would see an incomplete `Derived` class and
    // the checks would not work.

    CheckIsSame<ValueType, value_type_t<Derived>>();
    CheckIsSame<CorpusType, corpus_type_t<Derived>>();
    static_assert(has_custom_corpus_type == Derived::has_custom_corpus_type);
  }

  std::unique_ptr<UntypedDomainInterface> Clone() const final {
    return std::make_unique<Derived>(derived());
  }

  GenericDomainCorpusType UntypedInit(absl::BitGenRef prng) final {
    return GenericDomainCorpusType(std::in_place_type<CorpusType>,
                                   derived().Init(prng));
  }

  void UntypedMutate(GenericDomainCorpusType& val, absl::BitGenRef prng,
                     bool only_shrink) final {
    derived().Mutate(val.GetAs<CorpusType>(), prng, only_shrink);
  }

  void UntypedUpdateMemoryDictionary(const GenericDomainCorpusType& val) final {
    derived().UpdateMemoryDictionary(val.GetAs<CorpusType>());
  }

  ValueType TypedGetValue(const GenericDomainCorpusType& v) const final {
    return derived().GetValue(v.GetAs<CorpusType>());
  }

  std::optional<GenericDomainCorpusType> TypedFromValue(
      const ValueType& v) const final {
    if (auto c = derived().FromValue(v)) {
      return GenericDomainCorpusType(std::in_place_type<CorpusType>,
                                     *std::move(c));
    } else {
      return std::nullopt;
    }
  }

  std::optional<GenericDomainCorpusType> UntypedParseCorpus(
      const IRObject& obj) const final {
    if (auto res = derived().ParseCorpus(obj)) {
      return GenericDomainCorpusType(std::in_place_type<CorpusType>,
                                     *std::move(res));
    } else {
      return std::nullopt;
    }
  }

  IRObject UntypedSerializeCorpus(
      const GenericDomainCorpusType& v) const final {
    return derived().SerializeCorpus(v.template GetAs<CorpusType>());
  }

  absl::Status UntypedValidateCorpusValue(
      const GenericDomainCorpusType& corpus_value) const final {
    return derived().ValidateCorpusValue(corpus_value.GetAs<CorpusType>());
  }

  uint64_t UntypedCountNumberOfFields(const GenericDomainCorpusType& v) final {
    return derived().CountNumberOfFields(v.GetAs<CorpusType>());
  }

  uint64_t UntypedMutateSelectedField(GenericDomainCorpusType& v,
                                      absl::BitGenRef prng, bool only_shrink,
                                      uint64_t selected_field_index) final {
    return derived().MutateSelectedField(v.GetAs<CorpusType>(), prng,
                                         only_shrink, selected_field_index);
  }

  int UntypedPrintCorpusValue(const GenericDomainCorpusType& val,
                              absl::FormatRawSink out, internal::PrintMode mode,
                              std::optional<int> tuple_elem) const override {
    FUZZTEST_INTERNAL_CHECK(
        !tuple_elem.has_value(),
        "No tuple element should be specified for this override.");
    internal::PrintValue(derived(), val.GetAs<CorpusType>(), out, mode);
    return -1;
  }

  // Default GetValue and FromValue functions for !has_custom_corpus_type
  // domains.
  ValueType GetValue(const ValueType& v) const {
    static_assert(!has_custom_corpus_type);
    return v;
  }
  std::optional<ValueType> FromValue(const ValueType& v) const {
    static_assert(!has_custom_corpus_type);
    return v;
  }

  std::optional<CorpusType> ParseCorpus(const IRObject& obj) const {
    static_assert(!has_custom_corpus_type);
    return obj.ToCorpus<CorpusType>();
  }

  IRObject SerializeCorpus(const CorpusType& v) const {
    static_assert(!has_custom_corpus_type);
    return IRObject::FromCorpus(v);
  }

  void UpdateMemoryDictionary(const CorpusType& val) {}

  uint64_t CountNumberOfFields(const CorpusType&) { return 0; }

  uint64_t MutateSelectedField(CorpusType&, absl::BitGenRef, bool, uint64_t) {
    return 0;
  }

  // Stores `seeds` to be occasionally sampled from during value initialization.
  // When called multiple times, appends to the previously added seeds.
  //
  // Note: Beware of the weird corner case when calling `.WithSeeds({0})`. This
  // will result in an ambiguous call, since `{0}` can be interpreted as
  // `std::function`. Use `.WithSeeds(std::vector{0})` instead.
  std::enable_if_t<std::is_copy_constructible_v<CorpusType>, Derived&>
  WithSeeds(const std::vector<ValueType>& seeds) {
    seeds_.reserve(seeds_.size() + seeds.size());
    for (const ValueType& seed : seeds) {
      std::optional<CorpusType> corpus_value = derived().FromValue(seed);
      if (!corpus_value.has_value()) {
        ReportBadSeedAndExit(
            seed,
            absl::InvalidArgumentError(
                "Seed could not be converted to the internal corpus value"));
      }

      absl::Status valid = derived().ValidateCorpusValue(*corpus_value);
      if (!valid.ok()) ReportBadSeedAndExit(seed, valid);

      seeds_.push_back(*std::move(corpus_value));
    }
    return derived();
  }

  // The type of a function that generates a vector of seeds.
  using SeedProvider = std::function<std::vector<ValueType>()>;

  // Stores `seed_provider` to be called lazily the first time the seeds are
  // needed. The generated seeds are appended to any explicitly stored seeds.
  //
  // This overload can be used when the seeds need to be initialized
  // dynamically. For example, if the seeds depend on any global variables, this
  // is a way to resolve the static initialization order fiasco.
  std::enable_if_t<std::is_copy_constructible_v<CorpusType>, Derived&>
  WithSeeds(SeedProvider seed_provider) {
    seed_provider_ = std::move(seed_provider);
    return derived();
  }

 protected:
  // `Derived::Init()` can use this to sample seeds for this domain.
  std::optional<CorpusType> MaybeGetRandomSeed(absl::BitGenRef prng) {
    if (seed_provider_ != nullptr) {
      WithSeeds(std::invoke(seed_provider_));
      seed_provider_ = nullptr;
    }

    static constexpr double kProbabilityToReturnSeed = 0.5;
    if (seeds_.empty() || !absl::Bernoulli(prng, kProbabilityToReturnSeed)) {
      return std::nullopt;
    }
    return seeds_[ChooseOffset(seeds_.size(), prng)];
  }

 private:
  Derived& derived() { return static_cast<Derived&>(*this); }
  const Derived& derived() const { return static_cast<const Derived&>(*this); }

  static void ReportBadSeedAndExit(const ValueType& seed,
                                   const absl::Status& status) {
    // This may run during fuzz test registration (i.e., global variable
    // initialization), so we can't use `GetStderr()`.
    absl::FPrintF(stderr, "[!] Invalid seed value (%s):\n\n{",
                  status.ToString());
    AutodetectTypePrinter<ValueType>().PrintUserValue(
        seed, &std::cerr, PrintMode::kHumanReadable);
    absl::FPrintF(stderr, "}\n");
    std::exit(1);
  }

  std::vector<CorpusType> seeds_;
  SeedProvider seed_provider_;
};

}  //  namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_DOMAIN_BASE_H_
