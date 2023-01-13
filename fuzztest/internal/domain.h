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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAIN_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAIN_H_

#include <algorithm>
#include <array>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/numeric/bits.h"
#include "absl/numeric/int128.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzztest/internal/any.h"
#include "./fuzztest/internal/coverage.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/regexp.h"
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
  static_assert(std::is_same_v<std::remove_const_t<T>, std::remove_const_t<U>>);
}

// Corpus value type used by Domain<T> template, regardless of T.
using GenericDomainCorpusType = CopyableAny;

// Base class for all domains.
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

// Given a parameter pack of functions `f`, run exactly one of the functions.
template <typename... F>
void RunOne(absl::BitGenRef prng, F... f) {
  ApplyIndex<sizeof...(F)>([&](auto... I) {
    int i = absl::Uniform<int>(prng, 0, sizeof...(F));
    ((i == I ? (void)f() : (void)0), ...);
  });
}

template <typename T, size_t N, typename F>
T ChooseOneOr(const T (&values)[N], absl::BitGenRef prng, F f) {
  int i = absl::Uniform<int>(absl::IntervalClosedClosed, prng, 0, N);
  return i == N ? f() : values[i];
}

// Random bit flip: minimal mutation to a field, it will converge
// the hamming distance of a value to its target in constant steps.
template <typename T>
void RandomBitFlip(absl::BitGenRef prng, T& val, size_t range) {
  using U = MakeUnsignedT<T>;
  U u = static_cast<U>(val);
  u ^= U{1} << absl::Uniform<int>(prng, 0, range);
  val = static_cast<T>(u);
}

// BitWidth of the value of val, specially handle uint12 and int128, because
// they don't have overloads in absl::bit_width.
template <typename T>
size_t BitWidth(T val) {
  if constexpr (std::is_same_v<T, absl::int128> ||
                std::is_same_v<T, absl::uint128>) {
    auto val_unsigned = MakeUnsignedT<T>(val);
    size_t res = 0;
    while (val_unsigned >>= 1) ++res;
    return res;
  } else {
    return absl::bit_width(static_cast<MakeUnsignedT<T>>(val));
  }
}

// Trying to copy a segment from `from` to `to`, with given offsets.
// Invalid offset that cause boundary check failures will make this function
// return false. `is_self` tells the function whether `from` and `to` points
// to the same object. Returns `true` iff copying results in `to` being mutated.
template <bool is_self, typename ContainerT>
bool CopyPart(const ContainerT& from, ContainerT& to,
              size_t from_segment_start_offset, size_t from_segment_size,
              size_t to_segment_start_offset, size_t max_size) {
  bool mutated = false;
  if (from_segment_size == 0) return mutated;
  size_t from_segment_end_offset =
      from_segment_start_offset + from_segment_size;
  size_t to_segment_end_offset = to_segment_start_offset + from_segment_size;
  if (from_segment_start_offset >= from.size() ||
      to_segment_start_offset > to.size() ||
      from_segment_end_offset > from.size() || to_segment_end_offset > max_size)
    return mutated;
  if (to_segment_end_offset > to.size()) {
    mutated = true;
    to.resize(to_segment_end_offset);
  } else {
    if (!std::equal(std::next(to.begin(), to_segment_start_offset),
                    std::next(to.begin(), to_segment_end_offset),
                    std::next(from.begin(), from_segment_start_offset),
                    std::next(from.begin(), from_segment_end_offset)))
      mutated = true;
  }
  if (!mutated) return mutated;
  if constexpr (!is_self) {
    std::copy(std::next(from.begin(), from_segment_start_offset),
              std::next(from.begin(), from_segment_end_offset),
              std::next(to.begin(), to_segment_start_offset));
  } else {
    ContainerT tmp(std::next(from.begin(), from_segment_start_offset),
                   std::next(from.begin(), from_segment_end_offset));
    std::copy(tmp.begin(), tmp.end(),
              std::next(to.begin(), to_segment_start_offset));
  }
  return mutated;
}

// Trying to insert a segment from `from` to `to`, with given offsets.
// Invalid offset that cause boundary check failures will make this function
// return false. `is_self` tells the function whether `from` and `to` points
// to the same object. Returns `true` iff insertion results in `to` being
// mutated.
template <bool is_self, typename ContainerT>
bool InsertPart(const ContainerT& from, ContainerT& to,
                size_t from_segment_start_offset, size_t from_segment_size,
                size_t to_segment_start_offset, size_t max_size) {
  bool mutated = false;
  if (from_segment_size == 0) return mutated;
  size_t from_segment_end_offset =
      from_segment_start_offset + from_segment_size;
  if (from_segment_start_offset >= from.size() ||
      to_segment_start_offset > to.size() ||
      from_segment_end_offset > from.size() ||
      from_segment_size > max_size - to.size())
    return mutated;
  mutated = true;
  if constexpr (!is_self) {
    to.insert(std::next(to.begin(), to_segment_start_offset),
              std::next(from.begin(), from_segment_start_offset),
              std::next(from.begin(), from_segment_end_offset));
  } else {
    ContainerT tmp(std::next(from.begin(), from_segment_start_offset),
                   std::next(from.begin(), from_segment_end_offset));
    to.insert(std::next(to.begin(), to_segment_start_offset), tmp.begin(),
              tmp.end());
  }
  return mutated;
}

template <typename T>
T SampleFromUniformRange(absl::BitGenRef prng, T min, T max) {
  return absl::Uniform(absl::IntervalClosedClosed, prng, min, max);
}

// Randomly apply Randomwalk or Uniform distribution or dictionary to mutate
// the val:
//  RandomWalk: converge the absolute distance of a value to its target
//  more efficiently.
//  Uniform Distribution: go across some non-linear boundary that cannot
//  be solved by bit flipping or randomwalk.
//  Dictionary: if applicable, choose randomly from the dictionary. if
//  dictionary fails to mutate, fall back to uniform.
template <unsigned char RANGE, typename T, typename IntegerDictionaryT>
void RandomWalkOrUniformOrDict(absl::BitGenRef prng, T& val, T min, T max,
                               const IntegerDictionaryT& temporary_dict,
                               const IntegerDictionaryT& permanent_dict,
                               std::optional<T>& permanent_dict_candidate) {
  constexpr bool is_memory_dictionary_compatible_integer =
      std::numeric_limits<T>::is_integer &&
      (sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8);
  const bool can_use_memory_dictionary =
      is_memory_dictionary_compatible_integer &&
      GetExecutionCoverage() != nullptr;
  const int action_count = 2 + can_use_memory_dictionary;
  int action = absl::Uniform(prng, 0, action_count);
  // Random walk.
  if (action-- == 0) {
    if (max / 2 - min / 2 <= RANGE) {
      val = SampleFromUniformRange(prng, min, max);
    } else {
      T lo = min;
      T hi = max;
      if (val > lo + RANGE) lo = val - RANGE;
      if (val < hi - RANGE) hi = val + RANGE;
      val = SampleFromUniformRange(prng, lo, hi);
    }
    return;
  }
  // Random choose.
  if (action-- == 0) {
    val = SampleFromUniformRange(prng, min, max);
    return;
  }
  // Dictionary
  if constexpr (is_memory_dictionary_compatible_integer) {
    if (can_use_memory_dictionary) {
      if (action-- == 0) {
        RunOne(
            prng,
            [&] {
              if (temporary_dict.IsEmpty()) {
                val = SampleFromUniformRange(prng, min, max);
              } else {
                val = temporary_dict.GetRandomSavedEntry(prng);
                permanent_dict_candidate = val;
              }
            },
            [&] {
              if (permanent_dict.IsEmpty()) {
                val = SampleFromUniformRange(prng, min, max);
              } else {
                val = permanent_dict.GetRandomSavedEntry(prng);
              }
            },
            [&] {
              auto entry = IntegerDictionary<T>::GetRandomTORCEntry(
                  val, prng,
                  GetExecutionCoverage()->GetTablesOfRecentCompares(), min,
                  max);
              if (entry.has_value()) {
                val = *entry;
              } else {
                val = SampleFromUniformRange(prng, min, max);
              }
            });
      }
    }
  }
}

inline size_t GetOrGuessPositionHint(std::optional<size_t> position_hint,
                                     size_t max, absl::BitGenRef prng) {
  if (position_hint.has_value()) {
    return *position_hint;
  } else {
    return ChooseOffset(max, prng);
  }
}

// Try to copy `dict_entry.value` to `val`:
// If `dict_entry` has a position hint, copy to that offset; otherwise,
// guess a position hint. Return the copied-to position if mutation succeed,
// otherwise std::nullopt. Return true iff `val` is successfully mutated.
template <bool is_self, typename ContainerT>
bool CopyFromDictionaryEntry(const DictionaryEntry<ContainerT>& dict_entry,
                             absl::BitGenRef prng, ContainerT& val,
                             size_t max_size) {
  if (dict_entry.value.size() >= max_size) return false;
  size_t position_hint = GetOrGuessPositionHint(
      dict_entry.position_hint,
      std::min(val.size(), max_size - dict_entry.value.size()), prng);
  return CopyPart<is_self>(dict_entry.value, val, 0, dict_entry.value.size(),
                           position_hint, max_size);
}

// The same as above, but set `permanent_dict_candidate` iff successfully
// mutated.
template <bool is_self, typename ContainerT>
bool CopyFromDictionaryEntry(
    const DictionaryEntry<ContainerT>& dict_entry, absl::BitGenRef prng,
    ContainerT& val, size_t max_size,
    std::optional<DictionaryEntry<ContainerT>>& permanent_dict_candidate) {
  if (dict_entry.value.size() >= max_size) return false;
  size_t position_hint = GetOrGuessPositionHint(
      dict_entry.position_hint,
      std::min(val.size(), max_size - dict_entry.value.size()), prng);
  bool mutated =
      CopyPart<is_self>(dict_entry.value, val, 0, dict_entry.value.size(),
                        position_hint, max_size);
  if (mutated) {
    permanent_dict_candidate = {position_hint, val};
  }
  return mutated;
}

// Try to insert `dict_entry.value` to `val`:
// If `dict_entry` has a position hint, copy to that offset; otherwise,
// guess a position hint. Return the inserted-to position if mutation succeed,
// otherwise std::nullopt. Return true iff successfully mutated.
template <bool is_self, typename ContainerT>
bool InsertFromDictionaryEntry(const DictionaryEntry<ContainerT>& dict_entry,
                               absl::BitGenRef prng, ContainerT& val,
                               size_t max_size) {
  if (dict_entry.value.size() >= max_size) return false;
  size_t position_hint =
      GetOrGuessPositionHint(dict_entry.position_hint, val.size(), prng);
  return InsertPart<is_self>(dict_entry.value, val, 0, dict_entry.value.size(),
                             position_hint, max_size);
}

// The same as above, but set `permanent_dict_candidate` iff successfully
// mutated.
template <bool is_self, typename ContainerT>
bool InsertFromDictionaryEntry(
    const DictionaryEntry<ContainerT>& dict_entry, absl::BitGenRef prng,
    ContainerT& val, size_t max_size,
    std::optional<DictionaryEntry<ContainerT>>& permanent_dict_candidate) {
  if (dict_entry.value.size() >= max_size) return false;
  size_t position_hint =
      GetOrGuessPositionHint(dict_entry.position_hint, val.size(), prng);
  bool mutated =
      InsertPart<is_self>(dict_entry.value, val, 0, dict_entry.value.size(),
                          position_hint, max_size);
  if (mutated) {
    permanent_dict_candidate = {position_hint, val};
  }
  return mutated;
}

template <typename ContainerT>
bool ApplyDictionaryMutationAndSavePermanentCandidate(
    ContainerT& val, const DictionaryEntry<ContainerT>& entry,
    absl::BitGenRef prng,
    std::optional<DictionaryEntry<ContainerT>>& permanent_dict_candidate,
    size_t max_size) {
  bool mutated = false;
  RunOne(
      prng,
      // Temporary dictionary replace contents from position hint.
      [&] {
        mutated = CopyFromDictionaryEntry<false>(entry, prng, val, max_size,
                                                 permanent_dict_candidate);
      },
      // Temporary dictionary insert into position hint.
      [&] {
        mutated = InsertFromDictionaryEntry<false>(entry, prng, val, max_size,
                                                   permanent_dict_candidate);
      });
  return mutated;
}

// Replace or insert the dictionary contents to position hints.
template <typename ContainerT>
bool MemoryDictionaryMutation(
    ContainerT& val, absl::BitGenRef prng,
    ContainerDictionary<ContainerT>& temporary_dict,
    ContainerDictionary<ContainerT>& manual_dict,
    ContainerDictionary<ContainerT>& permanent_dict,
    std::optional<DictionaryEntry<ContainerT>>& permanent_dict_candidate,
    size_t max_size) {
  bool mutated = false;
  const bool can_use_manual_dictionary = !manual_dict.IsEmpty();
  const bool can_use_temporary_dictionary = !temporary_dict.IsEmpty();
  const bool can_use_permanent_dictionary = !permanent_dict.IsEmpty();
  const int dictionary_action_count = 1 + can_use_manual_dictionary +
                                      can_use_temporary_dictionary +
                                      can_use_permanent_dictionary;
  int dictionary_action = absl::Uniform(prng, 0, dictionary_action_count);
  if (can_use_temporary_dictionary && dictionary_action-- == 0) {
    mutated = ApplyDictionaryMutationAndSavePermanentCandidate(
        val, temporary_dict.GetRandomSavedEntry(prng), prng,
        permanent_dict_candidate, max_size);
  }
  if (can_use_manual_dictionary && dictionary_action-- == 0) {
    mutated = ApplyDictionaryMutationAndSavePermanentCandidate(
        val, manual_dict.GetRandomSavedEntry(prng), prng,
        permanent_dict_candidate, max_size);
  }
  if (can_use_permanent_dictionary && dictionary_action-- == 0) {
    RunOne(
        prng,
        // Permanent dictionary replace contents from position hint.
        [&] {
          mutated = CopyFromDictionaryEntry<false>(
              permanent_dict.GetRandomSavedEntry(prng), prng, val, max_size);
        },
        // Permanent dictionary insert into position hint.
        [&] {
          mutated = InsertFromDictionaryEntry<false>(
              permanent_dict.GetRandomSavedEntry(prng), prng, val, max_size);
        });
  }
  // Pick entries from tables_of_recent_compares(TORC) directly.
  if (dictionary_action-- == 0) {
    auto dictionary_entry = ContainerDictionary<ContainerT>::GetRandomTORCEntry(
        val, prng, GetExecutionCoverage()->GetTablesOfRecentCompares());
    if (dictionary_entry.has_value()) {
      mutated = ApplyDictionaryMutationAndSavePermanentCandidate(
          val, *dictionary_entry, prng, permanent_dict_candidate, max_size);
    }
  }
  return mutated;
}

// Randomly erases a contiguous chunk of at least 1 and at most half the
// elements in `val`. The final size of `val` will be at least `min_size`.
template <typename ContainerT>
void EraseRandomChunk(ContainerT& val, absl::BitGenRef prng, size_t min_size) {
  if (val.size() <= min_size) return;
  size_t chunk_size =
      absl::Uniform(absl::IntervalClosedClosed, prng, size_t{1},
                    std::min(val.size() - min_size, val.size() >> 1));
  size_t chunk_offset = ChooseOffset(val.size() - chunk_size, prng);
  auto it_start = std::next(val.begin(), chunk_offset);
  auto it_end = std::next(it_start, chunk_size);
  val.erase(it_start, it_end);
}

// Randomly inserts `new_element_val` at least 1 and at most 15 times at a
// random position in `val`. The final size of `val` will be at most `max_size`.
template <typename ContainerT, typename T>
void InsertRandomChunk(ContainerT& val, absl::BitGenRef prng, size_t max_size,
                       T new_element_val) {
  if (val.size() >= max_size) return;
  size_t grows = absl::Uniform(absl::IntervalClosedClosed, prng, size_t{1},
                               std::min(max_size - val.size(), size_t{15}));
  size_t grow_offset = ChooseOffset(val.size(), prng);
  while (grows--) {
    val.insert(std::next(val.begin(), grow_offset), new_element_val);
  }
}

// Helper serialization functions for common patterns: optional/variant/tuple.
template <typename... Domain>
IRObject SerializeWithDomainVariant(
    const std::tuple<Domain...>& domains,
    const std::variant<corpus_type_t<Domain>...>& v) {
  IRObject obj;
  auto& subs = obj.MutableSubs();
  subs.push_back(IRObject::FromCorpus(v.index()));
  Switch<sizeof...(Domain)>(v.index(), [&](auto I) {
    subs.push_back(std::get<I>(domains).SerializeCorpus(std::get<I>(v)));
  });
  return obj;
}

template <typename... Domain,
          typename ReturnT = std::variant<corpus_type_t<Domain>...>>
std::optional<ReturnT> ParseWithDomainVariant(
    const std::tuple<Domain...>& domains, const IRObject& obj) {
  auto subs = obj.Subs();
  if (!subs || subs->size() != 2) return std::nullopt;

  auto alternative = (*subs)[0].GetScalar<size_t>();
  if (!alternative || *alternative >= sizeof...(Domain)) return std::nullopt;

  return Switch<sizeof...(Domain)>(
      *alternative, [&](auto I) -> std::optional<ReturnT> {
        auto inner_corpus = std::get<I>(domains).ParseCorpus((*subs)[1]);
        if (!inner_corpus) return std::nullopt;
        return ReturnT(std::in_place_index<I>, *std::move(inner_corpus));
      });
}

template <typename Domain>
auto SerializeWithDomainOptional(
    const Domain& domain,
    const std::variant<std::monostate, corpus_type_t<Domain>>& v) {
  IRObject obj;
  auto& subs = obj.MutableSubs();
  subs.push_back(IRObject(v.index()));
  if (v.index() == 1) {
    subs.push_back(domain.SerializeCorpus(std::get<1>(v)));
  }
  return obj;
}

template <typename Domain, typename ReturnT = std::variant<
                               std::monostate, corpus_type_t<Domain>>>
std::optional<ReturnT> ParseWithDomainOptional(const Domain& domain,
                                               const IRObject& obj) {
  auto subs = obj.Subs();
  if (!subs || subs->empty()) return std::nullopt;
  auto index = (*subs)[0].GetScalar<size_t>();
  if (index == 0) {
    if (subs->size() != 1) return std::nullopt;
    return ReturnT();
  } else if (index == 1) {
    if (subs->size() != 2) return std::nullopt;
    auto inner_corpus = domain.ParseCorpus((*subs)[1]);
    if (!inner_corpus) return std::nullopt;
    return ReturnT(std::in_place_index<1>, *std::move(inner_corpus));
  } else {
    return std::nullopt;
  }
}

template <typename... Domain>
auto SerializeWithDomainTuple(
    const std::tuple<Domain...>& domains,
    const std::tuple<corpus_type_t<Domain>...>& corpus) {
  IRObject obj;
  auto& subs = obj.MutableSubs();
  ApplyIndex<sizeof...(Domain)>([&](auto... I) {
    (subs.push_back(std::get<I>(domains).SerializeCorpus(std::get<I>(corpus))),
     ...);
  });
  return obj;
}

// Parse a corpus given a tuple of domains, skipping the first `skip` subs.
template <typename... Domain>
std::optional<std::tuple<corpus_type_t<Domain>...>> ParseWithDomainTuple(
    const std::tuple<Domain...>& domains, const IRObject& obj, int skip = 0) {
  auto subs = obj.Subs();
  if (!subs || subs->size() != sizeof...(Domain) + skip) return std::nullopt;
  return ApplyIndex<sizeof...(Domain)>([&](auto... I) {
    return [](auto... opts) {
      return (!opts || ...)
                 ? std::nullopt
                 : std::optional(std::tuple<corpus_type_t<Domain>...>{
                       *std::move(opts)...});
    }(std::get<I>(domains).ParseCorpus((*subs)[I + skip])...);
  });
}

template <typename T, typename = void>
class ArbitraryImpl {
  static_assert(always_false<T>,
                "=> Type not supported yet. Consider filing an issue."
  );
};

// Capture const values. This is a workaround in order to enable
// Arbitrary<std::map<std::string, int>>() and similar container domains that
// require Arbitrary<std::pair< _const_ std::string, int>>() to be defined,
// which in turn requires Arbitrary<const std::string>() to be defined.
template <typename T>
class ArbitraryImpl<const T> : public ArbitraryImpl<T> {};

// For monostate types with a default constructor, just give the single value.
template <typename T>
class ArbitraryImpl<T, std::enable_if_t<is_monostate_v<T>>>
    : public DomainBase<ArbitraryImpl<T>> {
 public:
  using value_type = T;

  value_type Init(absl::BitGenRef) { return value_type{}; }

  void Mutate(value_type&, absl::BitGenRef, bool) {}

  auto GetPrinter() const { return MonostatePrinter{}; }
};

// REQUIRES: |target| < |val|
template <typename T>
T ShrinkTowards(absl::BitGenRef prng, T val, T target) {
  if (val < target) {
    return absl::Uniform(absl::IntervalOpenClosed, prng, val, target);
  } else {
    return absl::Uniform(absl::IntervalClosedOpen, prng, target, val);
  }
}

template <>
class ArbitraryImpl<bool> : public DomainBase<ArbitraryImpl<bool>> {
 public:
  using value_type = bool;

  value_type Init(absl::BitGenRef prng) {
    return static_cast<bool>(absl::Uniform(prng, 0, 2));
  }

  void Mutate(value_type& val, absl::BitGenRef, bool only_shrink) {
    if (only_shrink) {
      val = false;
    } else {
      val = !val;
    }
  }

  auto GetPrinter() const { return IntegralPrinter{}; }
};

template <typename T>
class ArbitraryImpl<T, std::enable_if_t<!std::is_const_v<T> &&
                                        std::numeric_limits<T>::is_integer>>
    : public DomainBase<ArbitraryImpl<T>> {
 public:
  using value_type = T;
  static constexpr bool is_memory_dictionary_compatible_v =
      sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8;
  using IntegerDictionaryT =
      std::conditional_t<is_memory_dictionary_compatible_v,
                         IntegerDictionary<T>, bool>;

  value_type Init(absl::BitGenRef prng) {
    const auto choose_from_all = [&] {
      return absl::Uniform(absl::IntervalClosedClosed, prng,
                           std::numeric_limits<T>::min(),
                           std::numeric_limits<T>::max());
    };
    if constexpr (sizeof(T) == 1) {
      return choose_from_all();
    } else {
      static constexpr T special[] = {
          T{0}, T{1},
          // For some types, ~T{} is promoted to int. Convert back to T.
          static_cast<T>(~T{}),
          std::numeric_limits<T>::is_signed
              ? std::numeric_limits<T>::max()
              : std::numeric_limits<T>::max() >> 1};
      return ChooseOneOr(special, prng, choose_from_all);
    }
  }

  void Mutate(value_type& val, absl::BitGenRef prng, bool only_shrink) {
    permanent_dict_candidate_ = std::nullopt;
    if (only_shrink) {
      if (val == 0) return;
      val = ShrinkTowards(prng, val, T{0});
      return;
    }
    const T prev = val;
    do {
      // Randomly apply 4 kinds of mutations with equal probabilities.
      // Use permanent_dictionary_ or temporary_dictionary_ with equal
      // probabilities.
      if (absl::Bernoulli(prng, 0.25)) {
        RandomBitFlip(prng, val, sizeof(T) * 8);
      } else {
        RandomWalkOrUniformOrDict<5>(prng, val, std::numeric_limits<T>::min(),
                                     std::numeric_limits<T>::max(),
                                     temporary_dict_, permanent_dict_,
                                     permanent_dict_candidate_);
      }
      // Make sure Mutate really mutates.
    } while (val == prev);
  }

  void UpdateMemoryDictionary(const value_type& val) {
    if constexpr (is_memory_dictionary_compatible_v) {
      if (GetExecutionCoverage() != nullptr) {
        temporary_dict_.MatchEntriesFromTableOfRecentCompares(
            val, GetExecutionCoverage()->GetTablesOfRecentCompares(),
            std::numeric_limits<T>::min(), std::numeric_limits<T>::max());
        if (permanent_dict_candidate_.has_value() &&
            permanent_dict_.Size() < kPermanentDictMaxSize) {
          permanent_dict_.AddEntry(std::move(*permanent_dict_candidate_));
          permanent_dict_candidate_ = std::nullopt;
        }
      }
    }
  }

  auto GetPrinter() const { return IntegralPrinter{}; }

 private:
  // Matched snapshots from table of recent compares.
  // It's the "unverified" dictionary entries: the mutated
  // value matched something in this snapshot, but not sure
  // if it will lead to new coverage.
  IntegerDictionaryT temporary_dict_;
  // Set of dictionary entries from previous `temporary_dict_`
  // that leads to new coverage. This is based on a heuristic
  // that such entries may lead to interesting behaviors even
  // after the first new coverage it triggered.
  IntegerDictionaryT permanent_dict_;
  std::optional<T> permanent_dict_candidate_;
  static constexpr size_t kPermanentDictMaxSize = 512;
};

template <typename T>
class ArbitraryImpl<T, std::enable_if_t<std::is_floating_point_v<T>>>
    : public DomainBase<ArbitraryImpl<T>> {
 public:
  using value_type = T;

  value_type Init(absl::BitGenRef prng) {
    const T special[] = {
        T{0.0}, T{-0.0}, T{1.0}, T{-1.0}, std::numeric_limits<T>::max(),
        std::numeric_limits<T>::infinity(), -std::numeric_limits<T>::infinity(),
        // std::nan is double. Cast to T explicitly.
        static_cast<T>(std::nan(""))};
    return ChooseOneOr(special, prng,
                       [&] { return absl::Uniform(prng, T{0}, T{1}); });
  }

  void Mutate(value_type& val, absl::BitGenRef prng, bool only_shrink) {
    if (only_shrink) {
      if (!std::isfinite(val) || val == 0) return;
      val = ShrinkTowards(prng, val, T{0});
      return;
    }
    const T prev = val;
    do {
      // If it is not finite we can't change it a bit because it would stay the
      // same. eg inf/2 == inf.
      if (!std::isfinite(val)) {
        val = Init(prng);
      } else {
        RunOne(
            prng,                    //
            [&] { val = val / 2; },  //
            [&] { val = -val; },     //
            [&] { val = val + 1; },  //
            [&] { val = val * 3; });
      }

      // Make sure Mutate really mutates.
    } while (val == prev || (std::isnan(prev) && std::isnan(val)));
  }

  auto GetPrinter() const { return FloatingPrinter{}; }
};

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
        val.size() >= this->min_size_ && val.size() <= this->max_size_,
        "Value has wrong size!");

    const bool can_shrink = val.size() > this->min_size_;
    const bool can_grow = !only_shrink && val.size() < this->max_size_;
    const bool can_change = val.size() != 0;
    const bool can_use_memory_dict = container_has_memory_dict && can_change &&
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

template <typename T>
class ArbitraryImpl<
    T, std::enable_if_t<always_true<T>,
                        decltype(
                            // Iterable
                            T().begin(), T().end(), T().size(),
                            // Values are mutable
                            // This rejects associative containers, for example
                            // *T().begin() = std::declval<typename
                            // T::value_type>(), Can insert and erase elements
                            T().insert(T().end(),
                                       std::declval<typename T::value_type>()),
                            T().erase(T().begin()),
                            //
                            (void)0)>>
    : public ContainerOfImpl<T, ArbitraryImpl<typename T::value_type>> {};

template <typename T>
class InRangeImpl : public DomainBase<InRangeImpl<T>> {
 public:
  using value_type = T;
  constexpr static bool T_is_integer = std::numeric_limits<T>::is_integer;
  constexpr static bool T_is_signed = std::is_signed<T>::value;
  constexpr static bool T_is_memory_dictionary_compatible =
      std::is_integral_v<T> &&
      (sizeof(T) == 1 || sizeof(T) == 2 || sizeof(T) == 4 || sizeof(T) == 8);
  using IntegerDictionaryT =
      std::conditional_t<T_is_memory_dictionary_compatible,
                         IntegerDictionary<T>, bool>;

  explicit InRangeImpl(T min, T max) : min_(min), max_(max) {
    FUZZTEST_INTERNAL_CHECK_PRECONDITION(min < max,
                                         "min must be smaller than max!");
    if constexpr (!T_is_integer) {
      FUZZTEST_INTERNAL_CHECK_PRECONDITION(
          !(min == std::numeric_limits<T>::lowest() &&
            max == std::numeric_limits<T>::max()),
          "Consider using the Finite<T>() domain instead.");
      FUZZTEST_INTERNAL_CHECK_PRECONDITION(std::isfinite(max - min),
                                           "Range is too large!");
    }
    if constexpr (T_is_integer) {
      // Find the longest common prefix
      // (from the most significant bit to the least significant bit) of
      // min_ and max_, and we only mutate the bits after the prefix.
      // This way it can somehow restrict the bit flipping range, but it
      // may still fail for range like [0b10000000, 0b01111111] which has
      // no valid bit flipping mutations.
      // We need to split the signed type range to positve range and
      // negative range because of their two's complement representation.
      if constexpr (T_is_signed) {
        if (min_ < 0 && max_ >= 0) {
          largest_mutable_bit_negative = BitWidth(~min);
          largest_mutable_bit_positive = BitWidth(max);
        } else if (min_ >= 0) {
          largest_mutable_bit_positive = BitWidth(min ^ max);
        } else if (max_ < 0) {
          largest_mutable_bit_negative = BitWidth(min ^ max);
        }
      } else {
        largest_mutable_bit_positive = BitWidth(min ^ max);
      }
    }
  }

  value_type Init(absl::BitGenRef prng) {
    // TODO(sbenzaquen): Add more interesting points in the range.
    const T special[] = {min_, max_};
    return ChooseOneOr(special, prng, [&] {
      return absl::Uniform(absl::IntervalClosedClosed, prng, min_, max_);
    });
  }

  void Mutate(value_type& val, absl::BitGenRef prng, bool only_shrink) {
    permanent_dict_candidate_ = std::nullopt;
    if (val < min_ || val > max_) {
      val = Init(prng);
      return;
    }
    if (only_shrink) {
      // Shrink towards zero, limiting to the range.
      T limit;
      if (max_ <= T{0}) {
        limit = max_;
      } else if (min_ >= T{0}) {
        limit = min_;
      } else {
        limit = T{0};
      }
      if (val == limit) return;
      val = ShrinkTowards(prng, val, limit);
      return;
    }
    const T prev = val;
    do {
      // Randomly apply 3 types of mutations, similarly to Arbitrary.
      if constexpr (T_is_integer) {
        // Random bit flip.
        if constexpr (T_is_signed) {
          if (absl::Bernoulli(prng, 0.25)) {
            if (prev >= 0) {
              RandomBitFlip(prng, val, largest_mutable_bit_positive);
            } else {
              RandomBitFlip(prng, val, largest_mutable_bit_negative);
            }
            if (max_ < val || val < min_) {
              val = absl::Uniform(absl::IntervalClosedClosed, prng, min_, max_);
            }
          } else {
            RandomWalkOrUniformOrDict<5>(prng, val, min_, max_, temporary_dict_,
                                         permanent_dict_,
                                         permanent_dict_candidate_);
          }
        } else {
          if (absl::Bernoulli(prng, 0.25)) {
            RandomBitFlip(prng, val, largest_mutable_bit_positive);
            if (max_ < val || val < min_) {
              val = absl::Uniform(absl::IntervalClosedClosed, prng, min_, max_);
            }
          } else {
            RandomWalkOrUniformOrDict<5>(prng, val, min_, max_, temporary_dict_,
                                         permanent_dict_,
                                         permanent_dict_candidate_);
          }
        }
      } else {
        RandomWalkOrUniformOrDict<5>(prng, val, min_, max_, temporary_dict_,
                                     permanent_dict_,
                                     permanent_dict_candidate_);
      }
    } while (val == prev);  // Make sure Mutate really mutates.
  }

  std::optional<value_type> ParseCorpus(const IRObject& obj) const {
    auto as_corpus = obj.ToCorpus<value_type>();
    if (!as_corpus || *as_corpus > max_ || *as_corpus < min_) {
      return std::nullopt;
    }
    return as_corpus;
  }

  auto GetPrinter() const {
    if constexpr (std::numeric_limits<T>::is_integer) {
      return IntegralPrinter{};
    } else {
      return FloatingPrinter{};
    }
  }

  void UpdateMemoryDictionary(const value_type& val) {
    if constexpr (T_is_memory_dictionary_compatible) {
      if (GetExecutionCoverage() != nullptr) {
        temporary_dict_.MatchEntriesFromTableOfRecentCompares(
            val, GetExecutionCoverage()->GetTablesOfRecentCompares(), min_,
            max_);
        if (permanent_dict_candidate_.has_value() &&
            permanent_dict_.Size() < kPermanentDictMaxSize) {
          permanent_dict_.AddEntry(std::move(*permanent_dict_candidate_));
          permanent_dict_candidate_ = std::nullopt;
        }
      }
    }
  }

 private:
  T min_;
  T max_;
  size_t largest_mutable_bit_positive = 0;
  size_t largest_mutable_bit_negative = 0;
  IntegerDictionaryT temporary_dict_ = {};
  IntegerDictionaryT permanent_dict_ = {};
  std::optional<T> permanent_dict_candidate_ = std::nullopt;
  static constexpr size_t kPermanentDictMaxSize = 512;
};

template <typename T>
class ElementOfImpl : public DomainBase<ElementOfImpl<T>> {
 public:
  using value_type = T;
  enum class corpus_type : size_t;
  static constexpr bool has_custom_corpus_type = true;

  explicit ElementOfImpl(std::vector<T> values) : values_(values) {
    FUZZTEST_INTERNAL_CHECK_PRECONDITION(
        !values.empty(), "ElementOf requires a non empty list.");
  }

  corpus_type Init(absl::BitGenRef prng) {
    return corpus_type{absl::Uniform<size_t>(prng, 0, values_.size())};
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    if (values_.size() <= 1) return;
    if (only_shrink) {
      size_t index = static_cast<size_t>(val);
      if (index == 0) return;
      index = absl::Uniform<size_t>(prng, 0, index);
      val = static_cast<corpus_type>(index);
      return;
    }
    // Choose a different index.
    size_t offset = absl::Uniform<size_t>(prng, 1, values_.size());
    size_t index = static_cast<size_t>(val);
    index += offset;
    if (index >= values_.size()) index -= values_.size();
    val = static_cast<corpus_type>(index);
  }

  value_type GetValue(corpus_type value) const {
    return values_[static_cast<size_t>(value)];
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    // For simple scalar types we try to find them in the list.
    // Otherwise, we fail unconditionally because we might not be able to
    // effectively compare the values.
    // Checking for `operator==` is not enough. You will have false positives
    // where `operator==` exists but it either doens't compile or it gives the
    // wrong answer.
    if constexpr (std::is_enum_v<value_type> ||
                  std::is_arithmetic_v<value_type> ||
                  std::is_same_v<std::string, value_type> ||
                  std::is_same_v<std::string_view, value_type>) {
      auto it = std::find(values_.begin(), values_.end(), v);
      return it == values_.end() ? std::nullopt
                                 : std::optional(static_cast<corpus_type>(
                                       it - values_.begin()));
    }
    return std::nullopt;
  }

  auto GetPrinter() const { return AutodetectTypePrinter<T>(); }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    auto as_corpus = obj.ToCorpus<corpus_type>();
    if (!as_corpus || static_cast<size_t>(*as_corpus) >= values_.size())
      return std::nullopt;
    return as_corpus;
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return IRObject::FromCorpus(v);
  }

 private:
  std::vector<T> values_;
};

template <typename... Inner>
class OneOfImpl
    : public DomainBase<OneOfImpl<Inner...>,
                        typename std::tuple_element_t<
                            0, typename std::tuple<Inner...>>::value_type> {
 public:
  // All value_types of inner domains must be the same. (Though note that they
  // can have different corpus_types!)
  using value_type =
      typename std::tuple_element_t<0,
                                    typename std::tuple<Inner...>>::value_type;
  static_assert(std::conjunction_v<
                    std::is_same<value_type, typename Inner::value_type>...>,
                "All domains in a OneOf must have the same value_type.");

  static constexpr bool has_custom_corpus_type = true;
  using corpus_type = std::variant<corpus_type_t<Inner>...>;

  explicit OneOfImpl(Inner... domains) : domains_(std::move(domains)...) {}

  corpus_type Init(absl::BitGenRef prng) {
    // TODO(b/191368509): Consider the cardinality of the subdomains to weight
    // them.
    return Switch<sizeof...(Inner)>(
        absl::Uniform(prng, size_t{}, num_domains_), [&](auto I) {
          return corpus_type(std::in_place_index<I>,
                             std::get<I>(domains_).Init(prng));
        });
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    // Switch to another domain 1% of the time when not reducing.
    if (num_domains_ > 1 && !only_shrink && absl::Bernoulli(prng, 0.01)) {
      // Choose a different index.
      size_t offset = absl::Uniform<size_t>(prng, 1, num_domains_);
      size_t index = static_cast<size_t>(val.index());
      index += offset;
      if (index >= num_domains_) index -= num_domains_;
      Switch<sizeof...(Inner)>(index, [&](auto I) {
        auto& domain = std::get<I>(domains_);
        val.template emplace<I>(domain.Init(prng));
      });
    } else {
      Switch<sizeof...(Inner)>(val.index(), [&](auto I) {
        auto& domain = std::get<I>(domains_);
        domain.Mutate(std::get<I>(val), prng, only_shrink);
      });
    }
  }

  value_type GetValue(const corpus_type& v) const {
    return Switch<sizeof...(Inner)>(v.index(), [&](auto I) -> value_type {
      auto domain = std::get<I>(domains_);
      return domain.GetValue(std::get<I>(v));
    });
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    std::optional<corpus_type> res;
    const auto try_one_corpus = [&](auto I) {
      if (auto inner_res = std::get<I>(domains_).FromValue(v)) {
        res.emplace(std::in_place_index<I>, *std::move(inner_res));
        return true;
      }
      return false;
    };

    ApplyIndex<sizeof...(Inner)>([&](auto... I) {
      // Try them in order, break on first success.
      (try_one_corpus(I) || ...);
    });

    return res;
  }

  auto GetPrinter() const { return OneOfPrinter<Inner...>{domains_}; }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    return ParseWithDomainVariant(domains_, obj);
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return SerializeWithDomainVariant(domains_, v);
  }

 private:
  std::tuple<Inner...> domains_;
  static_assert(std::tuple_size_v<decltype(domains_)> > 0,
                "OneOf requires a non-empty list.");
  // For ease of reading.
  const size_t num_domains_ = sizeof...(Inner);
};

template <typename T>
class BitFlagCombinationOfImpl
    : public DomainBase<BitFlagCombinationOfImpl<T>> {
 public:
  using value_type = T;

  explicit BitFlagCombinationOfImpl(absl::Span<const T> flags)
      : flags_(flags.begin(), flags.end()) {
    FUZZTEST_INTERNAL_CHECK_PRECONDITION(
        !flags.empty(), "BitFlagCombinationOf requires a non empty list.");
    // Make sure they are mutually exclusive options, and none are empty.
    for (int i = 0; i < flags.size(); ++i) {
      T v1 = flags[i];
      FUZZTEST_INTERNAL_CHECK_PRECONDITION(
          v1 != T{}, "BitFlagCombinationOf requires non zero flags.");
      for (int j = i + 1; j < flags.size(); ++j) {
        T v2 = flags[j];
        FUZZTEST_INTERNAL_CHECK_PRECONDITION(
            BitAnd(v1, v2) == T{},
            "BitFlagCombinationOf requires flags to be mutually exclusive.");
      }
    }
  }

  value_type Init(absl::BitGenRef) { return value_type{}; }

  void Mutate(value_type& val, absl::BitGenRef prng, bool only_shrink) {
    T to_switch = flags_[ChooseOffset(flags_.size(), prng)];

    if (!only_shrink || BitAnd(val, to_switch) != T{}) {
      val = BitXor(val, to_switch);
    }
  }

  auto GetPrinter() const { return AutodetectTypePrinter<T>(); }

 private:
  template <typename U>
  static value_type BitAnd(U a, U b) {
    if constexpr (std::is_enum_v<U>) {
      return BitAnd(static_cast<std::underlying_type_t<U>>(a),
                    static_cast<std::underlying_type_t<U>>(b));
    } else {
      return static_cast<value_type>(a & b);
    }
  }

  template <typename U>
  static value_type BitXor(U a, U b) {
    if constexpr (std::is_enum_v<U>) {
      return BitXor(static_cast<std::underlying_type_t<U>>(a),
                    static_cast<std::underlying_type_t<U>>(b));
    } else {
      return static_cast<value_type>(a ^ b);
    }
  }

  std::vector<value_type> flags_;
};

class InRegexpImpl : public DomainBase<InRegexpImpl, std::string> {
 public:
  using DFAPath = std::vector<RegexpDFA::Edge>;
  using value_type = std::string;
  using corpus_type = DFAPath;

  static constexpr bool has_custom_corpus_type = true;

  explicit InRegexpImpl(std::string_view regex_str)
      : dfa_(RegexpDFA::Create(regex_str)) {}

  DFAPath Init(absl::BitGenRef prng) {
    std::optional<DFAPath> path =
        dfa_.StringToDFAPath(dfa_.GenerateString(prng));
    FUZZTEST_INTERNAL_CHECK_PRECONDITION(path.has_value(),
                                         "Init should generate valid paths");
    return *path;
  }

  // Strategy: Parse the input string into a path in the DFA. Pick a node in the
  // path and random walk from the node until we reach an end state or go back
  // to the original path.
  void Mutate(DFAPath& path, absl::BitGenRef prng, bool only_shrink) {
    if (only_shrink) {
      // Fast path to remove loop.
      if (absl::Bernoulli(prng, 0.5)) {
        if (ShrinkByRemoveLoop(prng, path)) return;
      }

      if (ShrinkByFindShorterSubPath(prng, path)) return;
      return;
    }

    int rand_offset = absl::Uniform<int>(prng, 0u, path.size());
    // Maps states to the path index of their first appearance. We want the
    // mutation to be mininal, so if a state appears multiple times in the path,
    // we only keep the index of its first appearance.
    std::vector<std::optional<int>> sink_states_first_appearance(
        dfa_.state_count());
    for (int i = rand_offset; i < path.size(); ++i) {
      int state_id = path[i].from_state_id;
      if (sink_states_first_appearance[state_id].has_value()) continue;
      sink_states_first_appearance[state_id] = i;
    }
    std::vector<RegexpDFA::Edge> new_subpath = dfa_.FindPath(
        prng, path[rand_offset].from_state_id, sink_states_first_appearance);
    int to_state_id = new_subpath.back().from_state_id;
    new_subpath.pop_back();

    DFAPath new_path;
    for (size_t i = 0; i < rand_offset; ++i) {
      new_path.push_back(path[i]);
    }
    for (size_t i = 0; i < new_subpath.size(); ++i) {
      new_path.push_back(new_subpath[i]);
    }

    // Found a node in the original path, so we append the remaining substring
    // of the original path.
    if (sink_states_first_appearance[to_state_id].has_value()) {
      for (size_t i = *sink_states_first_appearance[to_state_id];
           i < path.size(); ++i) {
        new_path.push_back(path[i]);
      }
    }
    FUZZTEST_INTERNAL_CHECK(
        dfa_.StringToDFAPath(*dfa_.DFAPathToString(new_path)).has_value(),
        "Mutation generate invalid strings");
    path = std::move(new_path);
  }

  auto GetPrinter() const { return StringPrinter{}; }

  value_type GetValue(const corpus_type& v) const {
    std::optional<std::string> val = dfa_.DFAPathToString(v);
    FUZZTEST_INTERNAL_CHECK(val.has_value(), "Corpus is invalid!");
    return *val;
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    return dfa_.StringToDFAPath(v);
  }

  IRObject SerializeCorpus(const corpus_type& path) const {
    IRObject obj;
    auto& subs = obj.MutableSubs();
    for (const auto& edge : path) {
      subs.push_back(IRObject::FromCorpus(edge.from_state_id));
      subs.push_back(IRObject::FromCorpus(edge.edge_index));
    }
    return obj;
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    auto subs = obj.Subs();
    if (!subs) return std::nullopt;
    if (subs->size() % 2 != 0) return std::nullopt;
    corpus_type res;
    for (size_t i = 0; i < subs->size(); i += 2) {
      auto from_state_id = (*subs)[i].ToCorpus<int>();
      auto edge_index = (*subs)[i + 1].ToCorpus<int>();
      if (!from_state_id.has_value() || !edge_index.has_value())
        return std::nullopt;
      res.push_back(RegexpDFA::Edge{*from_state_id, *edge_index});
    }

    // Check whether this is a valid path in the DFA.
    if (!dfa_.DFAPathToString(res).has_value()) return std::nullopt;
    return res;
  }

 private:
  // Remove a random loop in the DFA path and return the string from the
  // modified path. A loop is a subpath that starts and ends with the same
  // state.
  bool ShrinkByRemoveLoop(absl::BitGenRef prng, DFAPath& path) {
    std::vector<std::vector<int>> state_appearances(dfa_.state_count());
    for (int i = 0; i < path.size(); ++i) {
      state_appearances[path[i].from_state_id].push_back(i);
    }
    std::vector<int> states_with_loop;
    for (int i = 0; i < dfa_.state_count(); ++i) {
      if (state_appearances[i].size() > 1) states_with_loop.push_back(i);
    }
    if (!states_with_loop.empty()) {
      int rand_state_id = states_with_loop[absl::Uniform<int>(
          prng, 0, states_with_loop.size())];
      std::vector<int>& loop_indexes = state_appearances[rand_state_id];
      int loop_start = absl::Uniform<int>(prng, 0u, loop_indexes.size() - 1);
      int loop_end =
          absl::Uniform<int>(prng, loop_start + 1, loop_indexes.size());
      // Delete the detected loop.
      path.erase(path.begin() + loop_indexes[loop_start],
                 path.begin() + loop_indexes[loop_end]);
      FUZZTEST_INTERNAL_CHECK(
          dfa_.StringToDFAPath(*dfa_.DFAPathToString(path)).has_value(),
          "The mutated path is invalid!");
      return true;
    }
    return false;
  }

  // Randomly pick a subpath and try to replace it with a shorter one. As this
  // might fail we keep trying until success or the maximum number of trials is
  // reached.
  bool ShrinkByFindShorterSubPath(absl::BitGenRef prng, DFAPath& path) {
    if (path.size() <= 1) {
      return false;
    }
    constexpr int n_trial = 40;
    constexpr int max_exploration_length = 100;
    for (int i = 0; i < n_trial; ++i) {
      // Pick any state in `path` as the start of the subpath, *except* the one
      // in the last element.
      int from_index = absl::Uniform<int>(prng, 0u, path.size() - 1);
      int from_state_id = path[from_index].from_state_id;

      // Pick a state after the "from state" as the end of the subpath.
      int to_index, to_state_id, length;
      if (i <= n_trial / 2) {
        // Pick any state in `path` after the "from state" as the end of the
        // subpath; this excludes the "end state".
        to_index =
            absl::Uniform<int>(prng, from_index + 1,
                               std::min(from_index + max_exploration_length,
                                        static_cast<int>(path.size())));
        to_state_id = path[to_index].from_state_id;
        length = to_index - from_index;
      } else {
        // If failing too many times, try to find a shorter path to the
        // end_state as a fall back. In this case, to_index isn't the index of
        // a valid element in `path`.
        to_index = static_cast<int>(path.size());
        to_state_id = dfa_.end_state_id();
        length = to_index - from_index;
      }

      if (length == 1) continue;

      std::vector<RegexpDFA::Edge> new_subpath = dfa_.FindPathWithinLengthDFS(
          prng, from_state_id, to_state_id, length);
      // If the size is unchanged, keep trying.
      if (new_subpath.size() == length) continue;

      DFAPath new_path(path.begin(), path.begin() + from_index);
      new_path.insert(new_path.end(), new_subpath.begin(), new_subpath.end());
      for (size_t idx = to_index; idx < path.size(); ++idx) {
        new_path.push_back(path[idx]);
      }
      FUZZTEST_INTERNAL_CHECK(
          dfa_.StringToDFAPath(*dfa_.DFAPathToString(new_path)).has_value(),
          "The mutated path is invalid!");
      path = std::move(new_path);
      return true;
    }
    return false;
  }
  RegexpDFA dfa_;
};

enum class RequireCustomCorpusType { kNo, kYes };

template <typename T, RequireCustomCorpusType require_custom, typename... Inner>
class AggregateOfImpl
    : public DomainBase<AggregateOfImpl<T, require_custom, Inner...>, T> {
 public:
  using value_type = T;
  // For user defined types (structs) we require a custom corpus_type
  // (std::tuple), because the serializer does not support structs, only tuples.
  static constexpr bool has_custom_corpus_type =
      require_custom == RequireCustomCorpusType::kYes ||
      (Inner::has_custom_corpus_type || ...);
  using corpus_type =
      std::conditional_t<has_custom_corpus_type,
                         std::tuple<corpus_type_t<Inner>...>, T>;

  AggregateOfImpl() = default;
  explicit AggregateOfImpl(std::in_place_t, Inner... inner)
      : inner_(std::move(inner)...) {}

  corpus_type Init(absl::BitGenRef prng) {
    return std::apply(
        [&](auto&... inner) { return corpus_type{inner.Init(prng)...}; },
        inner_);
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    std::integral_constant<int, sizeof...(Inner)> size;
    auto bound = internal::BindAggregate(val, size);
    // Filter the tuple to only the mutable fields.
    // The const ones can't be mutated.
    // Eg in `std::pair<const int, int>` for maps.
    static constexpr auto to_mutate =
        GetMutableSubtuple<decltype(internal::BindAggregate(std::declval<T&>(),
                                                            size))>();
    static constexpr size_t actual_size =
        std::tuple_size_v<decltype(to_mutate)>;
    if constexpr (actual_size > 0) {
      int offset = absl::Uniform<int>(prng, 0, actual_size);
      Switch<actual_size>(offset, [&](auto I) {
        std::get<to_mutate[I]>(inner_).Mutate(std::get<to_mutate[I]>(bound),
                                              prng, only_shrink);
      });
    }
  }

  void UpdateMemoryDictionary(const corpus_type& val) {
    // Copy codes from Mutate that does the mutable domain filtering things.
    std::integral_constant<int, sizeof...(Inner)> size;
    auto bound = internal::BindAggregate(val, size);
    static constexpr auto to_mutate =
        GetMutableSubtuple<decltype(internal::BindAggregate(std::declval<T&>(),
                                                            size))>();
    static constexpr size_t actual_size =
        std::tuple_size_v<decltype(to_mutate)>;
    // Apply UpdateMemoryDictionary to every mutable domain.
    if constexpr (actual_size > 0) {
      ApplyIndex<actual_size>([&](auto... I) {
        (std::get<to_mutate[I]>(inner_).UpdateMemoryDictionary(
             std::get<to_mutate[I]>(bound)),
         ...);
      });
    }
  }

  int UntypedPrintCorpusValue(const GenericDomainCorpusType& val,
                              absl::FormatRawSink out, internal::PrintMode mode,
                              std::optional<int> tuple_elem) const final {
    if (tuple_elem.has_value()) {
      if constexpr (sizeof...(Inner) != 0) {
        if (*tuple_elem >= 0 && *tuple_elem < sizeof...(Inner)) {
          Switch<sizeof...(Inner)>(*tuple_elem, [&](auto I) {
            PrintValue(std::get<I>(inner_),
                       std::get<I>(val.GetAs<corpus_type_t<AggregateOfImpl>>()),
                       out, mode);
          });
        }
      }
    } else {
      AggregateOfImpl::DomainBase::UntypedPrintCorpusValue(val, out, mode,
                                                           std::nullopt);
    }
    return sizeof...(Inner);
  }

  auto GetPrinter() const { return AggregatePrinter<Inner...>{inner_}; }

  value_type GetValue(const corpus_type& value) const {
    if constexpr (has_custom_corpus_type) {
      if constexpr (DetectBindableFieldCount<value_type>() ==
                    DetectBraceInitCount<value_type>()) {
        return ApplyIndex<sizeof...(Inner)>([&](auto... I) {
          return T{std::get<I>(inner_).GetValue(std::get<I>(value))...};
        });
      } else {
        // Right now the only other possibility is that the bindable field count
        // is one less than the brace init field count. In that case, that extra
        // field is used to initialize an empty base class. We'll need to update
        // this if that ever changes.
        return ApplyIndex<sizeof...(Inner)>([&](auto... I) {
          return T{{}, std::get<I>(inner_).GetValue(std::get<I>(value))...};
        });
      }
    } else {
      return value;
    }
  }

  std::optional<corpus_type> FromValue(const value_type& value) const {
    if constexpr (has_custom_corpus_type) {
      return ApplyIndex<sizeof...(Inner)>([&](auto... I) {
        auto bound = internal::BindAggregate(
            value, std::integral_constant<int, sizeof...(Inner)>{});
        return [](auto... optional_values) -> std::optional<corpus_type> {
          if ((optional_values.has_value() && ...)) {
            return std::tuple(*std::move(optional_values)...);
          } else {
            return std::nullopt;
          }
        }(std::get<I>(inner_).FromValue(std::get<I>(bound))...);
      });
    } else {
      return value;
    }
  }

  // Use the generic serializer when no custom corpus type is used, since it is
  // more efficient. Eg a string value can be serialized as a string instead of
  // as a sequence of char values.
  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    if constexpr (has_custom_corpus_type) {
      return ParseWithDomainTuple(inner_, obj);
    } else {
      return obj.ToCorpus<corpus_type>();
    }
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    if constexpr (has_custom_corpus_type) {
      return SerializeWithDomainTuple(inner_, v);
    } else {
      return IRObject::FromCorpus(v);
    }
  }

 private:
  template <typename Tuple>
  static constexpr auto GetMutableSubtuple() {
    return ApplyIndex<std::tuple_size_v<Tuple>>([](auto... I) {
      constexpr auto is_const = [](auto I2) {
        return std::is_const_v<
            std::remove_reference_t<std::tuple_element_t<I2, Tuple>>>;
      };
      std::array<int, (!is_const(I) + ... + 0)> res{};
      int pos = 0;
      ((is_const(I) ? I : res[pos++] = I), ...);
      return res;
    });
  }

  std::tuple<Inner...> inner_;
};

template <typename T, typename... Elem>
AggregateOfImpl<T, RequireCustomCorpusType::kYes, ArbitraryImpl<Elem>...>
    DetectAggregateOfImpl2(std::tuple<Elem&...>);

// Detect the number and types of the fields.
// TODO(sbenzaquen): Verify the compiler error in case we can't detect it and
// improve if possible.
template <typename T, int N = *DetectBindableFieldCount<T>()>
decltype(DetectAggregateOfImpl2<T>(
    BindAggregate(std::declval<T&>(), std::integral_constant<int, N>{})))
DetectAggregateOfImpl();

// Specialization for user-defined aggregate types.
template <typename T>
class ArbitraryImpl<
    T, std::enable_if_t<std::is_class_v<T> && std::is_aggregate_v<T> &&
                        // Monostates have their own domain.
                        !is_monostate_v<T> &&
                        // std::array uses the Tuple domain.
                        !is_array_v<T>>>
    : public decltype(DetectAggregateOfImpl<T>()) {};

template <typename T, typename U>
class ArbitraryImpl<std::pair<T, U>>
    : public AggregateOfImpl<
          std::pair<std::remove_const_t<T>, std::remove_const_t<U>>,
          std::is_const_v<T> || std::is_const_v<U>
              ? RequireCustomCorpusType::kYes
              : RequireCustomCorpusType::kNo,
          ArbitraryImpl<T>, ArbitraryImpl<U>> {};

template <typename... T>
class ArbitraryImpl<std::tuple<T...>, std::enable_if_t<sizeof...(T) != 0>>
    : public AggregateOfImpl<std::tuple<T...>, RequireCustomCorpusType::kNo,
                             ArbitraryImpl<T>...> {};

template <typename T, size_t N>
auto AggregateOfImplForArray() {
  return ApplyIndex<N>([&](auto... I) {
    return AggregateOfImpl<std::array<T, N>, RequireCustomCorpusType::kNo,
                           std::enable_if_t<(I >= 0), ArbitraryImpl<T>>...>{};
  });
}

template <typename T, size_t N>
class ArbitraryImpl<std::array<T, N>>
    : public decltype(AggregateOfImplForArray<T, N>()) {};

template <typename T, typename... Inner>
class VariantOfImpl : public DomainBase<VariantOfImpl<T, Inner...>> {
 public:
  using value_type = T;
  static constexpr bool has_custom_corpus_type = true;
  // `T` might be a custom variant type.
  // We use std::variant unconditionally to make it simpler.
  using corpus_type = std::variant<corpus_type_t<Inner>...>;

  VariantOfImpl() = default;
  explicit VariantOfImpl(std::in_place_t, Inner... inner)
      : inner_(std::move(inner)...) {}

  corpus_type Init(absl::BitGenRef prng) {
    return Switch<sizeof...(Inner)>(
        absl::Uniform(prng, size_t{}, sizeof...(Inner)), [&](auto I) {
          return corpus_type(std::in_place_index<I>,
                             std::get<I>(inner_).Init(prng));
        });
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    // Flip a coin to choose between generating a value of an alternative type
    // and mutating the value of the current type. Assign more weight to the
    // mutating case in order to explore more on a given type before we start
    // from scratch again.
    if (absl::Bernoulli(prng, 0.2)) {
      val = Init(prng);
    } else {
      Switch<sizeof...(Inner)>(val.index(), [&](auto I) {
        std::get<I>(inner_).Mutate(std::get<I>(val), prng, only_shrink);
      });
    }
  }

  auto GetPrinter() const { return VariantPrinter<Inner...>{inner_}; }

  value_type GetValue(const corpus_type& v) const {
    return Switch<sizeof...(Inner)>(v.index(), [&](auto I) -> value_type {
      value_type out;
      out.template emplace<I>(std::get<I>(inner_).GetValue(std::get<I>(v)));
      return out;
    });
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    return Switch<sizeof...(Inner)>(
        v.index(), [&](auto I) -> std::optional<corpus_type> {
          if (auto inner_value =
                  std::get<I>(inner_).FromValue(std::get<I>(v))) {
            return corpus_type(std::in_place_index<I>, *std::move(inner_value));
          } else {
            return std::nullopt;
          }
        });
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    return ParseWithDomainVariant(inner_, obj);
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return SerializeWithDomainVariant(inner_, v);
  }

 private:
  std::tuple<Inner...> inner_;
};

template <typename... T>
class ArbitraryImpl<std::variant<T...>>
    : public VariantOfImpl<std::variant<T...>, ArbitraryImpl<T>...> {};

enum class OptionalPolicy { kWithNull, kWithoutNull, kAlwaysNull };

template <typename T, typename InnerDomain>
class OptionalOfImpl : public DomainBase<OptionalOfImpl<T, InnerDomain>> {
 public:
  using value_type = T;
  static_assert(Requires<T>([](auto x) -> decltype(!x, *x) {}),
                "T must be an optional type.");
  static constexpr bool has_custom_corpus_type = true;
  // `T` might be a custom optional type.
  // We use std::variant unconditionally to make it simpler.
  using corpus_type = std::variant<std::monostate, corpus_type_t<InnerDomain>>;

  explicit OptionalOfImpl(InnerDomain inner)
      : inner_(std::move(inner)), policy_(OptionalPolicy::kWithNull) {}

  corpus_type Init(absl::BitGenRef prng) {
    if (policy_ == OptionalPolicy::kAlwaysNull ||
        // 1/2 chance of returning an empty to avoid initialization with large
        // entities for recursive data structures. See
        // ContainerOfImplBase::ChooseRandomSize for more details.
        (policy_ == OptionalPolicy::kWithNull && absl::Bernoulli(prng, 0.5))) {
      return corpus_type(std::in_place_index<0>);
    } else {
      return corpus_type(std::in_place_index<1>, inner_.Init(prng));
    }
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    if (policy_ == OptionalPolicy::kAlwaysNull) {
      val.template emplace<0>();
      return;
    }
    const bool has_value = val.index() == 1;
    if (!has_value) {
      // Only add a value if we are not shrinking.
      if (!only_shrink) val.template emplace<1>(inner_.Init(prng));
    } else if (policy_ == OptionalPolicy::kWithNull &&
               absl::Bernoulli(prng, 1. / 100)) {
      // 1/100 chance of returning an empty.
      val.template emplace<0>();
    } else {
      inner_.Mutate(std::get<1>(val), prng, only_shrink);
    }
  }

  auto GetPrinter() const {
    return OptionalPrinter<OptionalOfImpl, InnerDomain>{*this, inner_};
  }

  value_type GetValue(const corpus_type& v) const {
    if (v.index() == 0) {
      FUZZTEST_INTERNAL_CHECK(policy_ != OptionalPolicy::kWithoutNull,
                              "Value cannot be null!");
      return value_type();
    }
    FUZZTEST_INTERNAL_CHECK(policy_ != OptionalPolicy::kAlwaysNull,
                            "Value cannot be non-null!");
    return value_type(inner_.GetValue(std::get<1>(v)));
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    if (!v) {
      FUZZTEST_INTERNAL_CHECK(policy_ != OptionalPolicy::kWithoutNull,
                              "Value cannot be null!");
      return corpus_type(std::in_place_index<0>);
    }
    FUZZTEST_INTERNAL_CHECK(policy_ != OptionalPolicy::kAlwaysNull,
                            "Value cannot be non-null!");
    if (auto inner_value = inner_.FromValue(*v)) {
      return corpus_type(std::in_place_index<1>, *std::move(inner_value));
    } else {
      return std::nullopt;
    }
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    std::optional<corpus_type> result = ParseWithDomainOptional(inner_, obj);
    if (!result.has_value()) {
      return std::nullopt;
    }
    bool is_null = std::get_if<std::monostate>(&(*result));
    if ((is_null && policy_ == OptionalPolicy::kWithoutNull) ||
        (!is_null && policy_ == OptionalPolicy::kAlwaysNull)) {
      return std::nullopt;
    }
    return result;
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return SerializeWithDomainOptional(inner_, v);
  }

  OptionalOfImpl& SetAlwaysNull() {
    policy_ = OptionalPolicy::kAlwaysNull;
    return *this;
  }
  OptionalOfImpl& SetWithoutNull() {
    policy_ = OptionalPolicy::kWithoutNull;
    return *this;
  }

  uint64_t CountNumberOfFields(const corpus_type& val) {
    if (val.index() == 1) {
      return inner_.CountNumberOfFields(std::get<1>(val));
    }
    return 0;
  }

  uint64_t MutateSelectedField(corpus_type& val, absl::BitGenRef prng,
                               bool only_shrink,
                               uint64_t selected_field_index) {
    if (val.index() == 1) {
      return inner_.MutateSelectedField(std::get<1>(val), prng, only_shrink,
                                        selected_field_index);
    }
    return 0;
  }

  InnerDomain Inner() const { return inner_; }

 private:
  InnerDomain inner_;
  OptionalPolicy policy_;
};

template <typename T, typename Inner>
class SmartPointerOfImpl : public DomainBase<SmartPointerOfImpl<T, Inner>> {
  // We use the type erased version here to allow for recursion in smart pointer
  // domains.
  // It helps cut the recursion in type traits (like corpus_type) and the
  // indirection avoids having the domain contain itself by value.
  using RealInner = Domain<typename T::element_type>;
  using InnerFn = const RealInner& (*)();

 public:
  using value_type = T;
  static constexpr bool has_custom_corpus_type = true;
  using corpus_type =
      std::variant<std::monostate, typename RealInner::corpus_type>;

  // Since we allow for recursion in this domain, we want to delay the
  // construction of the inner domain. Otherwise we would have an infinite
  // recursion of domains being created.
  explicit SmartPointerOfImpl(InnerFn fn) : inner_(fn) {}
  explicit SmartPointerOfImpl(Inner inner) : inner_(std::move(inner)) {}

  corpus_type Init(absl::BitGenRef) {
    // Init will always have an empty smart pointer to reduce nesting.
    // Otherwise it is very easy to get a stack overflow during Init() when
    // there is recursion in the domains.
    return corpus_type();
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    const bool has_value = val.index() == 1;
    if (!has_value) {
      // Only add a value if we are not shrinking.
      if (!only_shrink) val.template emplace<1>(GetOrMakeInner().Init(prng));
    } else if (absl::Bernoulli(prng, 1. / 100)) {
      // 1/100 chance of returning an empty.
      val.template emplace<0>();
    } else {
      GetOrMakeInner().Mutate(std::get<1>(val), prng, only_shrink);
    }
  }

  auto GetPrinter() const {
    return OptionalPrinter<SmartPointerOfImpl, RealInner>{
        *this, GetOrMakeInnerConst()};
  }

  value_type GetValue(const corpus_type& v) const {
    if (v.index() == 0) return value_type();
    return value_type(new auto(GetOrMakeInnerConst().GetValue(std::get<1>(v))));
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    if (!v) return corpus_type(std::in_place_index<0>);
    if (auto inner_value = GetOrMakeInnerConst().FromValue(*v)) {
      return corpus_type(std::in_place_index<1>, *std::move(inner_value));
    } else {
      return std::nullopt;
    }
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    return ParseWithDomainOptional(GetOrMakeInnerConst(), obj);
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return SerializeWithDomainOptional(GetOrMakeInnerConst(), v);
  }

 private:
  RealInner& GetOrMakeInner() {
    if (inner_.index() == 0) {
      inner_.template emplace<1>(std::get<0>(inner_)());
    }
    return std::get<1>(inner_);
  }

  const RealInner& GetOrMakeInnerConst() const {
    return inner_.index() == 0 ? std::get<0>(inner_)() : std::get<1>(inner_);
  }

  // We don't construct it eagerly to avoid an infinite recursion during
  // default construction. We only construct the sub domain on demand.
  std::variant<InnerFn, RealInner> inner_;
};

template <typename T>
const Domain<T>& GetGlobalDomainDefaultInstance() {
  static const auto* instance = new Domain<T>(ArbitraryImpl<T>());
  return *instance;
}

template <typename T>
class ArbitraryImpl<std::optional<T>>
    : public OptionalOfImpl<std::optional<T>, ArbitraryImpl<T>> {
 public:
  ArbitraryImpl() : ArbitraryImpl::OptionalOfImpl(ArbitraryImpl<T>()) {}
};

template <typename T>
class ArbitraryImpl<std::unique_ptr<T>>
    : public SmartPointerOfImpl<std::unique_ptr<T>, ArbitraryImpl<T>> {
 public:
  ArbitraryImpl()
      : ArbitraryImpl::SmartPointerOfImpl(GetGlobalDomainDefaultInstance) {}
};

template <typename T>
class ArbitraryImpl<std::shared_ptr<T>>
    : public SmartPointerOfImpl<std::shared_ptr<T>, ArbitraryImpl<T>> {
 public:
  ArbitraryImpl()
      : ArbitraryImpl::SmartPointerOfImpl(GetGlobalDomainDefaultInstance) {}
};

template <typename Mapper, typename... Inner>
class MapImpl
    : public DomainBase<MapImpl<Mapper, Inner...>,
                        std::decay_t<std::invoke_result_t<
                            Mapper, const typename Inner::value_type&...>>> {
 public:
  using corpus_type = std::tuple<corpus_type_t<Inner>...>;
  using value_type = std::decay_t<
      std::invoke_result_t<Mapper, const typename Inner::value_type&...>>;
  static constexpr bool has_custom_corpus_type = true;

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

template <typename FlatMapper, typename... Inner>
class FlatMapImpl
    : public DomainBase<
          FlatMapImpl<FlatMapper, Inner...>,
          typename std::decay_t<std::invoke_result_t<
              FlatMapper, const typename Inner::value_type&...>>::value_type> {
 private:
  using output_domain = std::decay_t<
      std::invoke_result_t<FlatMapper, const typename Inner::value_type&...>>;

 public:
  using corpus_type =
      std::tuple<corpus_type_t<output_domain>, corpus_type_t<Inner>...>;
  using value_type = typename output_domain::value_type;
  static constexpr bool has_custom_corpus_type = true;

  FlatMapImpl() = default;
  explicit FlatMapImpl(FlatMapper mapper, Inner... inner)
      : mapper_(std::move(mapper)), inner_(std::move(inner)...) {}

  corpus_type Init(absl::BitGenRef prng) {
    auto inner_corpus = std::apply(
        [&](auto&... inner) { return std::make_tuple(inner.Init(prng)...); },
        inner_);
    auto output_domain = ApplyIndex<sizeof...(Inner)>([&](auto... I) {
      return mapper_(
          std::get<I>(inner_).GetValue(std::get<I>(inner_corpus))...);
    });
    return std::tuple_cat(std::make_tuple(output_domain.Init(prng)),
                          inner_corpus);
  }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    // There is no way to tell whether the current output corpus value is
    // consistent with a new output domain generated by mutated inputs, so
    // mutating the inputs forces re-initialization of the output domain. This
    // means that, when shrinking, we cannot mutate the inputs, as
    // re-initializing would lose the "still crashing" output value.
    bool mutate_inputs = !only_shrink && absl::Bernoulli(prng, 0.1);
    if (mutate_inputs) {
      ApplyIndex<sizeof...(Inner)>([&](auto... I) {
        // The first field of `val` is the output corpus value, so skip it.
        (std::get<I>(inner_).Mutate(std::get<I + 1>(val), prng, only_shrink),
         ...);
      });
      std::get<0>(val) = GetOutputDomain(val).Init(prng);
      return;
    }
    // For simplicity, we create a new output domain each call to `Mutate`. This
    // means that stateful domains don't work, but this is currently a matter of
    // convenience, not correctness. For example, `Filter` won't automatically
    // find when something is too restrictive.
    // TODO(b/246423623): Support stateful domains.
    GetOutputDomain(val).Mutate(std::get<0>(val), prng, only_shrink);
  }

  value_type GetValue(const corpus_type& v) const {
    return GetOutputDomain(v).GetValue(std::get<0>(v));
  }

  std::optional<corpus_type> FromValue(const value_type&) const {
    // We cannot infer the input corpus from the output value, or even determine
    // from which output domain the output value came.
    return std::nullopt;
  }

  auto GetPrinter() const {
    return FlatMappedPrinter<FlatMapper, Inner...>{mapper_, inner_};
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    auto inner_corpus = ParseWithDomainTuple(inner_, obj, /*skip=*/1);
    if (!inner_corpus.has_value()) {
      return std::nullopt;
    }
    auto output_domain = ApplyIndex<sizeof...(Inner)>([&](auto... I) {
      return mapper_(
          std::get<I>(inner_).GetValue(std::get<I>(*inner_corpus))...);
    });
    // We know obj.Subs()[0] exists because ParseWithDomainTuple succeeded.
    auto output_corpus = output_domain.ParseCorpus((*obj.Subs())[0]);
    if (!output_corpus.has_value()) {
      return std::nullopt;
    }
    return std::tuple_cat(std::make_tuple(*output_corpus), *inner_corpus);
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    auto domain = std::tuple_cat(std::make_tuple(GetOutputDomain(v)), inner_);
    return SerializeWithDomainTuple(domain, v);
  }

 private:
  output_domain GetOutputDomain(const corpus_type& val) const {
    return ApplyIndex<sizeof...(Inner)>([&](auto... I) {
      // The first field of `val` is the output corpus value, so skip it.
      return mapper_(std::get<I>(inner_).GetValue(std::get<I + 1>(val))...);
    });
  }
  FlatMapper mapper_;
  std::tuple<Inner...> inner_;
};

template <int&... ExplicitArgumentBarrier, typename Mapper, typename... Inner>
auto NamedMap(absl::string_view name, Mapper mapper, Inner... inner) {
  return internal::MapImpl<Mapper, Inner...>(name, std::move(mapper),
                                             std::move(inner)...);
}

template <typename Pred, typename Inner>
class FilterImpl
    : public DomainBase<FilterImpl<Pred, Inner>, typename Inner::value_type> {
 public:
  using corpus_type = corpus_type_t<Inner>;
  using value_type = typename Inner::value_type;
  static constexpr bool has_custom_corpus_type = Inner::has_custom_corpus_type;

  FilterImpl() = default;
  explicit FilterImpl(Pred predicate, Inner inner)
      : predicate_(std::move(predicate)), inner_(std::move(inner)) {}

  corpus_type Init(absl::BitGenRef prng) {
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

// UniqueElementsContainerImpl supports producing containers of type `T`, with
// elements of type `E` from domain `InnerDomain inner`, with a guarantee that
// each element of the container has a unique value from `InnerDomain`. The
// guarantee is provided by using a `absl::flat_hash_set<E>` as our corpus_type,
// which is (effectively) produced by `UnorderedSetOf(inner)`.
template <typename T, typename InnerDomain>
class UniqueElementsContainerImpl
    : public DomainBase<UniqueElementsContainerImpl<T, InnerDomain>> {
  using UniqueDomainValueT =
      absl::flat_hash_set<typename InnerDomain::value_type>;
  using UniqueDomain =
      AssociativeContainerOfImpl<UniqueDomainValueT, InnerDomain>;

 public:
  using value_type = T;
  using corpus_type = typename UniqueDomain::corpus_type;
  static constexpr bool has_custom_corpus_type = true;

  UniqueElementsContainerImpl() = default;
  explicit UniqueElementsContainerImpl(InnerDomain inner)
      : unique_domain_(std::move(inner)) {}

  // All of these methods delegate at least partially to the unique_domain_
  // member.

  corpus_type Init(absl::BitGenRef prng) { return unique_domain_.Init(prng); }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    unique_domain_.Mutate(val, prng, only_shrink);
  }

  value_type GetValue(const corpus_type& v) const {
    UniqueDomainValueT unique_values = unique_domain_.GetValue(v);
    return value_type(unique_values.begin(), unique_values.end());
  }

  std::optional<corpus_type> FromValue(const value_type& v) const {
    return unique_domain_.FromValue(
        typename UniqueDomain::value_type(v.begin(), v.end()));
  }

  auto GetPrinter() const { return unique_domain_.GetPrinter(); }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    return unique_domain_.ParseCorpus(obj);
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return unique_domain_.SerializeCorpus(v);
  }

  auto& WithSize(size_t s) { return WithMinSize(s).WithMaxSize(s); }
  auto& WithMinSize(size_t s) {
    unique_domain_.WithMinSize(s);
    return *this;
  }
  auto& WithMaxSize(size_t s) {
    unique_domain_.WithMaxSize(s);
    return *this;
  }

 private:
  UniqueDomain unique_domain_;
};

template <typename Char>
class ArbitraryImpl<std::basic_string_view<Char>>
    : public DomainBase<ArbitraryImpl<std::basic_string_view<Char>>> {
 public:
  using value_type = std::string_view;
  // We use a vector to better manage the buffer and help ASan find
  // out-of-bounds bugs.
  using corpus_type = std::vector<Char>;
  static constexpr bool has_custom_corpus_type = true;

  corpus_type Init(absl::BitGenRef prng) { return inner_.Init(prng); }

  void Mutate(corpus_type& val, absl::BitGenRef prng, bool only_shrink) {
    inner_.Mutate(val, prng, only_shrink);
  }

  void UpdateMemoryDictionary(const corpus_type& val) {
    inner_.UpdateMemoryDictionary(val);
  }

  auto GetPrinter() const { return StringPrinter{}; }

  value_type GetValue(const corpus_type& value) const {
    return value_type(value.data(), value.size());
  }

  std::optional<corpus_type> FromValue(const value_type& value) const {
    return corpus_type(value.begin(), value.end());
  }

  std::optional<corpus_type> ParseCorpus(const IRObject& obj) const {
    return obj.ToCorpus<corpus_type>();
  }

  IRObject SerializeCorpus(const corpus_type& v) const {
    return IRObject::FromCorpus(v);
  }

 private:
  ArbitraryImpl<std::vector<Char>> inner_;
};

template <>
class ArbitraryImpl<absl::Duration>
    : public OneOfImpl<ElementOfImpl<absl::Duration>,
                       MapImpl<absl::Duration (*)(int64_t, uint32_t),
                               ArbitraryImpl<int64_t>, InRangeImpl<uint32_t>>> {
 public:
  ArbitraryImpl()
      : OneOfImpl(
            ElementOfImpl<absl::Duration>(
                {absl::InfiniteDuration(), -absl::InfiniteDuration()}),
            MapImpl<absl::Duration (*)(int64_t, uint32_t),
                    ArbitraryImpl<int64_t>, InRangeImpl<uint32_t>>(
                [](int64_t secs, uint32_t ticks) {
                  return MakeDuration(secs, ticks);
                },
                ArbitraryImpl<int64_t>(),
                // ticks is 1/4 of a nanosecond and has a range of [0, 4B - 1]
                InRangeImpl<uint32_t>(0u, 3'999'999'999u))) {}
};

template <>
class ArbitraryImpl<absl::Time>
    : public MapImpl<absl::Time (*)(absl::Duration),
                     ArbitraryImpl<absl::Duration>> {
 public:
  ArbitraryImpl()
      : MapImpl<absl::Time (*)(absl::Duration), ArbitraryImpl<absl::Duration>>(
            [](absl::Duration duration) {
              return absl::UnixEpoch() + duration;
            },
            ArbitraryImpl<absl::Duration>()) {}
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAIN_H_
