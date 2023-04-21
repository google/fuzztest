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
#include <iostream>
#include <memory>
#include <optional>
#include <type_traits>
#include <vector>

#include "absl/random/bit_gen_ref.h"
#include "absl/random/distributions.h"
#include "absl/strings/str_format.h"
#include "absl/types/span.h"
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
using GenericCorpusValue = CopyableAny;

// Base class for all domains.
//
// It is "untyped" in that it erases all user_value_t/corpus_value_t inputs and
// outputs. This allows code sharing of the runtime.
// All the `Untyped[Name]` functions implement the same API as the `[Name]`
// function but marshalls the inputs and output through the generic types.
class UntypedDomainInterface {
 public:
  virtual ~UntypedDomainInterface() {}

  virtual std::unique_ptr<UntypedDomainInterface> Clone() const = 0;
  virtual GenericCorpusValue UntypedInit(absl::BitGenRef) = 0;
  virtual void UntypedMutate(GenericCorpusValue& val, absl::BitGenRef prng,
                             bool only_shrink) = 0;
  virtual void UntypedUpdateMemoryDictionary(const GenericCorpusValue& val) = 0;
  virtual std::optional<GenericCorpusValue> UntypedIrToCorpusValue(
      const IrValue& ir) const = 0;
  virtual bool UntypedValidateCorpusValue(
      const GenericCorpusValue& corpus_value) const = 0;
  virtual IrValue UntypedCorpusToIrValue(const GenericCorpusValue& v) const = 0;
  virtual uint64_t UntypedCountNumberOfFields(const GenericCorpusValue&) = 0;
  virtual uint64_t UntypedMutateSelectedField(GenericCorpusValue&,
                                              absl::BitGenRef, bool,
                                              uint64_t) = 0;
  virtual MoveOnlyAny UntypedCorpusToUserValue(
      const GenericCorpusValue& v) const = 0;
  // UntypedPrintCorpusValue is special in that it has an extra parameter
  // `tuple_elem`. This is used to instruct the `std::tuple` domain to print one
  // particular element instead of the whole tuple. This is what the runtime
  // uses to print out the arguments when a counterexample is found.
  // In the `std::tuple` case, it also returns the number of elements in the
  // tuple.
  virtual int UntypedPrintCorpusValue(
      const GenericCorpusValue& val, absl::FormatRawSink out,
      internal::PrintMode mode,
      std::optional<int> tuple_elem = std::nullopt) const = 0;
};

// A typed subinterface that provides the methods to handle `user_value_t`
// inputs/outputs. Some callers require the actual `user_value_t`.
template <typename UserValueT>
class TypedDomainInterface : public UntypedDomainInterface {
 public:
  virtual UserValueT TypedCorpusToUserValue(
      const GenericCorpusValue& v) const = 0;
  virtual std::optional<GenericCorpusValue> TypedUserToCorpusValue(
      const UserValueT& v) const = 0;

  MoveOnlyAny UntypedCorpusToUserValue(
      const GenericCorpusValue& v) const final {
    return MoveOnlyAny(std::in_place_type<UserValueT>,
                       TypedCorpusToUserValue(v));
  }
};

template <typename Derived,
          typename UserValueT = ExtractTemplateParameter<0, Derived>,
          typename CorpusValueT = UserValueT>
class DomainBase : public TypedDomainInterface<UserValueT> {
 public:
  using user_value_t = UserValueT;
  using corpus_value_t = CorpusValueT;
  static constexpr bool has_custom_corpus_value_t =
      !std::is_same_v<UserValueT, CorpusValueT>;

  DomainBase() {
    // Check that the interface of `Derived` matches the requirements for a
    // domain implementation. We check these inside the constructor of
    // `DomainBase`, where `Derived` is already fully defined. If we try to
    // check them at class scope we would see an incomplete `Derived` class and
    // the checks would not work.

    CheckIsSame<UserValueT, user_value_t_of<Derived>>();
    CheckIsSame<CorpusValueT, corpus_value_t_of<Derived>>();
    static_assert(has_custom_corpus_value_t ==
                  Derived::has_custom_corpus_value_t);
  }

  std::unique_ptr<UntypedDomainInterface> Clone() const final {
    return std::make_unique<Derived>(derived());
  }

  GenericCorpusValue UntypedInit(absl::BitGenRef prng) final {
    return GenericCorpusValue(std::in_place_type<CorpusValueT>,
                              derived().Init(prng));
  }

  void UntypedMutate(GenericCorpusValue& val, absl::BitGenRef prng,
                     bool only_shrink) final {
    derived().Mutate(val.GetAs<CorpusValueT>(), prng, only_shrink);
  }

  void UntypedUpdateMemoryDictionary(const GenericCorpusValue& val) final {
    derived().UpdateMemoryDictionary(val.GetAs<CorpusValueT>());
  }

  UserValueT TypedCorpusToUserValue(const GenericCorpusValue& v) const final {
    return derived().CorpusToUserValue(v.GetAs<CorpusValueT>());
  }

  std::optional<GenericCorpusValue> TypedUserToCorpusValue(
      const UserValueT& v) const final {
    if (auto c = derived().UserToCorpusValue(v)) {
      return GenericCorpusValue(std::in_place_type<CorpusValueT>,
                                *std::move(c));
    } else {
      return std::nullopt;
    }
  }

  std::optional<GenericCorpusValue> UntypedIrToCorpusValue(
      const IrValue& obj) const final {
    if (auto res = derived().IrToCorpusValue(obj)) {
      return GenericCorpusValue(std::in_place_type<CorpusValueT>,
                                *std::move(res));
    } else {
      return std::nullopt;
    }
  }

  IrValue UntypedCorpusToIrValue(const GenericCorpusValue& v) const final {
    return derived().CorpusToIrValue(v.template GetAs<CorpusValueT>());
  }

  bool UntypedValidateCorpusValue(
      const GenericCorpusValue& corpus_value) const final {
    return derived().ValidateCorpusValue(corpus_value.GetAs<CorpusValueT>());
  }

  uint64_t UntypedCountNumberOfFields(const GenericCorpusValue& v) final {
    return derived().CountNumberOfFields(v.GetAs<CorpusValueT>());
  }

  uint64_t UntypedMutateSelectedField(GenericCorpusValue& v,
                                      absl::BitGenRef prng, bool only_shrink,
                                      uint64_t selected_field_index) final {
    return derived().MutateSelectedField(v.GetAs<CorpusValueT>(), prng,
                                         only_shrink, selected_field_index);
  }

  int UntypedPrintCorpusValue(const GenericCorpusValue& val,
                              absl::FormatRawSink out, internal::PrintMode mode,
                              std::optional<int> tuple_elem) const override {
    FUZZTEST_INTERNAL_CHECK(
        !tuple_elem.has_value(),
        "No tuple element should be specified for this override.");
    internal::PrintValue(derived(), val.GetAs<CorpusValueT>(), out, mode);
    return -1;
  }

  // Default CorpusToUserValue and UserToCorpusValue functions for
  // !has_custom_corpus_value_t domains.
  UserValueT CorpusToUserValue(const UserValueT& v) const {
    static_assert(!has_custom_corpus_value_t);
    return v;
  }
  std::optional<UserValueT> UserToCorpusValue(const UserValueT& v) const {
    static_assert(!has_custom_corpus_value_t);
    return v;
  }

  std::optional<CorpusValueT> IrToCorpusValue(const IrValue& obj) const {
    static_assert(!has_custom_corpus_value_t);
    return obj.ToCorpus<CorpusValueT>();
  }

  IrValue CorpusToIrValue(const CorpusValueT& v) const {
    static_assert(!has_custom_corpus_value_t);
    return IrValue::FromCorpus(v);
  }

  void UpdateMemoryDictionary(const CorpusValueT& val) {}

  uint64_t CountNumberOfFields(const CorpusValueT&) { return 0; }

  uint64_t MutateSelectedField(CorpusValueT&, absl::BitGenRef, bool, uint64_t) {
    return 0;
  }

  // Stores `seeds` to be occasionally sampled from during value initialization.
  std::enable_if_t<std::is_copy_constructible_v<CorpusValueT>, Derived&>
  WithSeeds(absl::Span<const UserValueT> seeds) {
    seeds_.clear();
    seeds_.reserve(seeds.size());
    for (const UserValueT& seed : seeds) {
      std::optional<CorpusValueT> corpus_seed =
          derived().UserToCorpusValue(seed);
      if (!corpus_seed.has_value()) {
        // This may run during fuzz test registration (i.e., global variable
        // initialization), so we can't use `GetStderr()`.
        absl::FPrintF(stderr, "[!] Invalid seed value:\n\n{");
        AutodetectTypePrinter<UserValueT>().PrintUserValue(
            seed, &std::cerr, PrintMode::kHumanReadable);
        absl::FPrintF(stderr, "}\n");
        std::exit(1);
      }
      seeds_.push_back(*std::move(corpus_seed));
    }
    return derived();
  }

 protected:
  // `Derived::Init()` can use this to sample seeds for this domain.
  std::optional<CorpusValueT> MaybeGetRandomSeed(absl::BitGenRef prng) const {
    static constexpr double kProbabilityToReturnSeed = 0.5;
    if (seeds_.empty() || !absl::Bernoulli(prng, kProbabilityToReturnSeed)) {
      return std::nullopt;
    }
    return seeds_[ChooseOffset(seeds_.size(), prng)];
  }

 private:
  Derived& derived() { return static_cast<Derived&>(*this); }
  const Derived& derived() const { return static_cast<const Derived&>(*this); }

  std::vector<CorpusValueT> seeds_;
};

}  //  namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_DOMAIN_BASE_H_
