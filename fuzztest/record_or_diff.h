// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Incremental differential fuzzing: `fuzztest::RecordOrDiff()`.
//
// Call `RecordOrDiff(value, label)` in a FUZZ_TEST body to record observable
// outputs of the code under test. Replaying the corpus with
//
//   --fuzztest_record=<test|*> --fuzztest_corpus_database=<db>
//   --fuzztest_workdir_root=<abs dir>
//
// stores a baseline under <workdir_root>/baseline/. Replaying a changed version
// with `--fuzztest_diff=<test|*>` (and optional `--fuzztest_for=<duration>`)
// compares every recorded value with the baseline and fails with a diff and the
// input counterexample if any differs.
//
// Labels are the keys: they must be unique within one input execution (a
// duplicate label is a test failure), and calls are matched by label, so the
// call order does not matter. An unlabeled call uses the label "".
//
// Outside `--fuzztest_record` / `--fuzztest_diff` (normal fuzzing, unit-test
// runs, plain replay), `RecordOrDiff` is a no-op: it returns after one relaxed
// atomic load.

#ifndef FUZZTEST_FUZZTEST_RECORD_OR_DIFF_H_
#define FUZZTEST_FUZZTEST_RECORD_OR_DIFF_H_

#include <cmath>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include "absl/base/optimization.h"
#include "absl/functional/function_ref.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/domain.h"
#include "./fuzztest/internal/meta.h"
#include "./fuzztest/internal/printer.h"
#include "./fuzztest/internal/runtime.h"
#include "./fuzztest/internal/serialization.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest {

// Options common to all overloads.
template <typename T>
struct RecordOrDiffOptions {
  // The key of the recorded value. Must be unique within one input execution
  // (a duplicate label is reported as a test failure). Unlabeled calls use "".
  // Build unique labels in loops, e.g. absl::StrCat("item/", i).
  std::string label = "";
  // Optional equality. Returns true iff `expected` and `actual` are equivalent.
  // If unset, operator== is used (NaN==NaN for top-level floating point).
  // REQUIRED when T has no operator== (e.g. protos); otherwise the first call
  // in diff mode reports an error.
  std::function<bool(const T& expected, const T& actual)> comparator = nullptr;
  // Optional printer used in mismatch reports. If unset, the Arbitrary<T>()
  // domain printer (or, for the codec overload, an escaped byte dump) is used.
  std::function<std::string(const T&)> printer = nullptr;
};

// Serialization adapter for types without Arbitrary<T>() support or for
// cross-language byte compatibility. Both closures are required.
template <typename T>
struct DiffCodec {
  std::function<std::string(const T&)> serializer;
  std::function<std::optional<T>(std::string_view)> deserializer;
};

namespace internal {

// Non-template helpers, defined in record_or_diff.cc. None of them does any
// file I/O; the baseline is handled by the Centipede controller.

// Reports the duplicate `label` usage error.
void ReportRecordOrDiffDuplicateLabel(absl::string_view label);
// Reports that `type_name` has no operator== and no comparator was given.
void ReportRecordOrDiffMissingComparator(absl::string_view type_name,
                                         bool is_proto);
// Reports that the value of `label` could not be serialized.
void ReportRecordOrDiffSerializationFailure(absl::string_view label);
// Reports a DiffCodec without serializer or deserializer.
void ReportRecordOrDiffInvalidCodec(absl::string_view label);
// Returns `bytes` C-escaped, for printing serialized values.
std::string EscapeRecordOrDiffBytes(absl::string_view bytes);

template <typename T, typename = void>
struct IsDiffEqualityComparable : std::false_type {};
template <typename T>
struct IsDiffEqualityComparable<
    T, std::void_t<decltype(static_cast<bool>(std::declval<const T&>() ==
                                              std::declval<const T&>()))>>
    : std::true_type {};

template <typename T>
bool DefaultDiffEquals(const T& expected, const T& actual) {
  if constexpr (std::is_floating_point_v<T>) {
    return expected == actual || (std::isnan(expected) && std::isnan(actual));
  } else if constexpr (IsDiffEqualityComparable<T>::value) {
    return expected == actual;
  } else {
    return false;  // Unreachable: a comparator is required.
  }
}

// Default serialization: top-level enums by underlying value, everything else
// with the Arbitrary<T>() domain.
template <typename T>
std::optional<std::string> DefaultDiffSerialize(const T& value) {
  if constexpr (std::is_enum_v<T>) {
    return SerializeIRObject(IRObject(value));
  } else {
    auto domain = Arbitrary<T>();
    auto corpus = domain.FromValue(value);
    if (!corpus.has_value()) return std::nullopt;
    return SerializeIRObject(domain.SerializeCorpus(*corpus));
  }
}

// Decodes `bytes` and invokes `consume(expected)` while keeping the backing
// `corpus_type` alive on the stack. This avoids dangling views when `T` borrows
// from its domain corpus (e.g. `std::string_view` or `absl::string_view`).
template <typename T>
bool DefaultDiffWithDeserialized(absl::string_view bytes,
                                 absl::FunctionRef<void(const T&)> consume) {
  const std::optional<IRObject> obj = ParseIRObject(bytes);
  if (!obj.has_value()) return false;
  if constexpr (std::is_enum_v<T>) {
    const std::optional<T> expected = obj->GetScalar<T>();
    if (!expected.has_value()) return false;
    consume(*expected);
    return true;
  } else {
    auto domain = Arbitrary<T>();
    const auto corpus = domain.ParseCorpus(*obj);
    if (!corpus.has_value() || !domain.ValidateCorpusValue(*corpus).ok()) {
      return false;
    }
    const T expected = domain.GetValue(*corpus);
    consume(expected);
    return true;
  }
}

template <typename T>
std::string DefaultDiffPrint(const T& value) {
  if constexpr (std::is_enum_v<T>) {
    return absl::StrCat(GetTypeName<T>(), "(",
                        +static_cast<std::underlying_type_t<T>>(value), ")");
  } else {
    auto domain = Arbitrary<T>();
    auto corpus = domain.FromValue(value);
    if (!corpus.has_value()) return "<unprintable value>";
    std::string out;
    domain_implementor::PrintValue(
        domain, *corpus, &out, domain_implementor::PrintMode::kHumanReadable);
    return out;
  }
}

// The shared implementation of the overloads. REQUIRES: diff mode is active.
template <typename T>
void RecordOrDiffImpl(
    const T& value, const RecordOrDiffOptions<T>& options,
    absl::FunctionRef<std::optional<std::string>(const T&)> serialize,
    absl::FunctionRef<bool(absl::string_view,
                           absl::FunctionRef<void(const T&)>)>
        with_deserialized,
    absl::FunctionRef<std::string(const T&)> default_print) {
  Runtime& runtime = Runtime::instance();
  const std::string& label = options.label;
  const Runtime::DiffCallDisposition disposition = runtime.BeginDiffCall(label);
  if (disposition.kind == Runtime::DiffCallDisposition::Kind::kSkip) {
    return;
  }
  if (disposition.kind == Runtime::DiffCallDisposition::Kind::kDuplicateLabel) {
    ReportRecordOrDiffDuplicateLabel(label);
    return;
  }
  if constexpr (!IsDiffEqualityComparable<T>::value) {
    if (!options.comparator) {
      ReportRecordOrDiffMissingComparator(GetTypeName<T>(),
                                          is_protocol_buffer_v<T>);
      return;
    }
  }
  const auto print = [&](const T& v) {
    return options.printer ? options.printer(v) : default_print(v);
  };
  if (disposition.kind == Runtime::DiffCallDisposition::Kind::kRecord) {
    std::optional<std::string> payload = serialize(value);
    if (!payload.has_value()) {
      ReportRecordOrDiffSerializationFailure(label);
      return;
    }
    runtime.AppendDiffRecord(label, *std::move(payload));
    return;
  }
  if (disposition.kind ==
      Runtime::DiffCallDisposition::Kind::kValidateNoBaseline) {
    return;
  }
  if (!disposition.expected_payload.has_value()) {
    runtime.AddDiffMismatch(
        label, absl::StrCat("new output \"", label, "\" not in baseline"),
        "<no output>", print(value));
    return;
  }
  const bool decoded =
      with_deserialized(*disposition.expected_payload, [&](const T& expected) {
        const bool equal = options.comparator
                               ? options.comparator(expected, value)
                               : DefaultDiffEquals(expected, value);
        if (!equal) {
          runtime.AddDiffMismatch(label, "value differs", print(expected),
                                  print(value));
        }
      });
  if (!decoded) {
    runtime.AddDiffMismatch(
        label, "cannot decode baseline value",
        absl::StrCat("<undecodable: ", disposition.expected_payload->size(),
                     " bytes>"),
        print(value));
  }
}

}  // namespace internal

// Records `value` (record mode) or compares it with the baseline (validate
// mode), keyed by `options.label`. Serializes with Arbitrary<T>() (top-level
// enums by underlying value).
//
// Note: omit the second argument instead of passing `{}`; `RecordOrDiff(v, {})`
// is ambiguous between the overloads. Pass `RecordOrDiff(v, "x")`, construct
// `RecordOrDiffOptions<T>`, or (in C++20+) use `RecordOrDiff(v, {.label =
// "x"})`.
template <typename T>
void RecordOrDiff(const T& value, const RecordOrDiffOptions<T>& options = {}) {
  if (ABSL_PREDICT_TRUE(!internal::Runtime::instance().diff_active())) return;
  internal::RecordOrDiffImpl<T>(
      value, options,
      [](const T& v) { return internal::DefaultDiffSerialize<T>(v); },
      [](absl::string_view bytes, absl::FunctionRef<void(const T&)> consume) {
        return internal::DefaultDiffWithDeserialized<T>(bytes, consume);
      },
      [](const T& v) { return internal::DefaultDiffPrint<T>(v); });
}

// Convenience: label only.
template <typename T>
void RecordOrDiff(const T& value, absl::string_view label) {
  if (ABSL_PREDICT_TRUE(!internal::Runtime::instance().diff_active())) return;
  RecordOrDiffOptions<T> options;
  options.label = std::string(label);
  RecordOrDiff(value, options);
}

// Custom codec: never instantiates Arbitrary<T>().
template <typename T>
void RecordOrDiff(const T& value, const DiffCodec<T>& codec,
                  const RecordOrDiffOptions<T>& options = {}) {
  if (ABSL_PREDICT_TRUE(!internal::Runtime::instance().diff_active())) return;
  if (!codec.serializer || !codec.deserializer) {
    if (!internal::Runtime::instance().ShouldSkipDiffCall()) {
      internal::ReportRecordOrDiffInvalidCodec(options.label);
    }
    return;
  }
  internal::RecordOrDiffImpl<T>(
      value, options,
      [&codec](const T& v) -> std::optional<std::string> {
        return codec.serializer(v);
      },
      [&codec](absl::string_view bytes,
               absl::FunctionRef<void(const T&)> consume) {
        const std::optional<T> expected =
            codec.deserializer(std::string_view(bytes.data(), bytes.size()));
        if (!expected.has_value()) return false;
        consume(*expected);
        return true;
      },
      [&codec](const T& v) {
        return internal::EscapeRecordOrDiffBytes(codec.serializer(v));
      });
}

}  // namespace fuzztest

#endif  // FUZZTEST_FUZZTEST_RECORD_OR_DIFF_H_
