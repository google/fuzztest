// Copyright 2024 Google LLC
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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_DOMAIN_CONCEPT_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_DOMAIN_CONCEPT_H_

#include <cstdint>
#include <memory>
#include <optional>

#include "absl/random/bit_gen_ref.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "./fuzztest/internal/domains/domain_base.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest {

// Type erased version of the domain concept.
// It can be constructed from any object that follows the domain concept for the
// right `value_type`. This class implements the domain concept too.
// TODO(sbenzaquen): Document the domain concept when it is stable enough.

template <typename T>
class Domain {
 public:
  using value_type = T;
  using corpus_type = internal::GenericDomainCorpusType;
  static constexpr bool has_custom_corpus_type = true;

  // Intentionally not marked as explicit to allow implicit conversion from the
  // inner domain implementations.
  template <typename Inner, typename CorpusType>
  Domain(const internal::DomainBase<Inner, T, CorpusType>& inner)
      : inner_(new auto(static_cast<const Inner&>(inner))) {}

  Domain(const Domain& other) { *this = other; }
  Domain& operator=(const Domain& other) {
    inner_.reset(static_cast<internal::TypedDomainInterface<T>*>(
        other.inner_->Clone().release()));
    return *this;
  }
  // No default constructor or move operations to avoid a null state.

  // GetRandomValue() returns a random user value from the domain. This is
  // useful e.g., for generation-based black-box fuzzing, when coverage-guided
  // fuzzing is not possible, or for other use cases when manually sampling the
  // domain makes sense (e.g., getting random values for benchmarking). These
  // are the only uses cases when the users should use domains directly, and
  // this is the only method that the users should call.
  //
  // In general, GetRandomValue() doesn't provide any guarantees on the
  // distribution of the returned values.
  //
  // Note about stability: GetRandomValue() doesn't guarantee stability of the
  // generated values even if `prng` is seeded with a fixed seed. With a seeded
  // `prng`, it is possible to reproduce the sequence of generated values by
  // setting the environment variable FUZZTEST_PRNG_SEED to the value output to
  // stderr on the first invocation. However, this is only guaranteed to work
  // with the same version of the binary.
  //
  value_type GetRandomValue(absl::BitGenRef prng) {
    return inner_->TypedGetRandomValue(prng);
  }

  // The methods below are used by the FuzzTest framework and custom domain
  // implementations.

  // Init() generates a random value of corpus_type.
  //
  // The generated value can often be a "special value" (e.g., 0, MAX_INT, NaN,
  // infinity, empty vector, etc.). For basic, fixed sized data types (e.g.,
  // optional<int>) Init() might give any value. For variable-sized data types
  // (e.g., containers, linked lists, trees, etc) Init() typically returns a
  // smaller sized value. Larger sized values however can be created through
  // Mutate() calls.
  //
  // ENSURES: That Init() is non-deterministic, i.e., it doesn't always return
  // the same value. This is because Mutate() often relies on Init() giving
  // different values (e.g., when growing a std::set<T> and adding new T
  // values).
  corpus_type Init(absl::BitGenRef prng) { return inner_->UntypedInit(prng); }

  // Mutate() makes a relatively small modification on `val` of corpus_type.
  //
  // When `only_shrink` is enabled, the mutated value is always "simpler" (e.g.,
  // smaller).
  //
  // ENSURES: That the mutated value is not the same as the original.
  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    return inner_->UntypedMutate(val, prng, only_shrink);
  }

  // Try to update the dynamic memory dictionary.
  // If it propagates to a domain that's compatible with dynamic
  // dictionary, it will try to match and save dictionary entries from
  // dynamic data collected by SanCov.
  void UpdateMemoryDictionary(const corpus_type& val) {
    return inner_->UntypedUpdateMemoryDictionary(val);
  }

  auto GetPrinter() const { return Printer{*inner_}; }

  value_type GetValue(const corpus_type& v) const {
    return inner_->TypedGetValue(v);
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    return inner_->TypedFromValue(v);
  }

  // Parses corpus value _without validating it_. Validation must be done with
  // ValidateCorpusValue().
  //
  // TODO(lszekeres): Return StatusOr<corpus_type>.
  std::optional<corpus_type> ParseCorpus(const internal::IRObject& obj) const {
    return inner_->UntypedParseCorpus(obj);
  }

  internal::IRObject SerializeCorpus(const corpus_type& v) const {
    return inner_->UntypedSerializeCorpus(v);
  }

  // After creating a corpus value, either via ParseCorpus() or via FromValue()
  // this method is used to determine if the corpus value is valid.
  absl::Status ValidateCorpusValue(const corpus_type& corpus_value) const {
    return inner_->UntypedValidateCorpusValue(corpus_value);
  }

  // TODO(JunyangShao): Get rid of this API so it won't be exposed
  // to outside.
  // Return the field counts of `val` if `val` is
  // a `ProtobufDomainImpl::corpus_type`. Otherwise propagate it
  // to inner domains and returns the sum of inner results.
  uint64_t CountNumberOfFields(const corpus_type& val) {
    return inner_->UntypedCountNumberOfFields(val);
  }

  // Mutate the selected protobuf field using `selected_field_index`.
  // Return value is the same as CountNumberOfFields.
  uint64_t MutateSelectedField(corpus_type& val, absl::BitGenRef prng,
                               bool only_shrink,
                               uint64_t selected_field_index) {
    return inner_->UntypedMutateSelectedField(val, prng, only_shrink,
                                              selected_field_index);
  }

  auto Clone() const { return inner_->Clone(); }

 private:
  // Have a subinterface just for the type traits to not expose more than
  // necessary through GetPrinter().
  friend class DomainBuilder;

  struct Printer {
    const internal::UntypedDomainInterface& inner;
    void PrintCorpusValue(const corpus_type& val, absl::FormatRawSink out,
                          internal::PrintMode mode) const {
      inner.UntypedPrintCorpusValue(val, out, mode);
    }
  };

  std::unique_ptr<internal::TypedDomainInterface<T>> inner_;
};

}  // namespace fuzztest

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_DOMAIN_CONCEPT_H_
