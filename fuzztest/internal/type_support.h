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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_TYPE_SUPPORT_H_
#define FUZZTEST_FUZZTEST_INTERNAL_TYPE_SUPPORT_H_

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <tuple>
#include <type_traits>
#include <utility>

#include "absl/debugging/symbolize.h"
#include "absl/strings/escaping.h"
#include "absl/strings/match.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "absl/time/time.h"
#include "./fuzztest/internal/domains/absl_helpers.h"
#include "./fuzztest/internal/meta.h"

namespace fuzztest::internal {

template <typename Domain>
using value_type_t = typename Domain::value_type;

template <typename Domain>
using corpus_type_t = typename Domain::corpus_type;

// Return a best effort printer for type `T`.
// This is useful for cases where the domain can't figure out how to print the
// value.
// It implements a good printer for common known types and fallbacks to an
// "unknown" printer to prevent compile time errors.
template <typename T>
decltype(auto) AutodetectTypePrinter();

// Returns true iff type `T` has a known printer that isn't UnknownPrinter.
template <typename T>
constexpr bool HasKnownPrinter();

// If `needle` is present in `haystack`, consume everything until `needle` and
// return true. Otherwise, return false.
inline bool ConsumePrefixUntil(absl::string_view& haystack,
                               absl::string_view needle) {
  size_t pos = haystack.find(needle);
  if (pos == haystack.npos) return false;
  haystack.remove_prefix(pos + needle.size());
  return true;
}

inline void SkipAnonymous(absl::string_view& in) {
  while (ConsumePrefixUntil(in, "(anonymous namespace)::")) {
  }
}

template <typename T>
absl::string_view GetTypeName() {
#if defined(__clang__)
  // Format "std::string_view GetTypeName() [T = int]"
  absl::string_view v = __PRETTY_FUNCTION__;
  ConsumePrefixUntil(v, "[T = ");
  SkipAnonymous(v);
  absl::ConsumeSuffix(&v, "]");
  return v;
#else
  return "<TYPE>";
#endif
}

// Used only in the predicate `HasAbslStringify`.
struct DummySink {};

template <typename T, typename = void>
struct HasAbslStringify : std::false_type {};

template <typename T>
struct HasAbslStringify<
    T, std::enable_if_t<std::is_void_v<decltype(AbslStringify(
           std::declval<DummySink&>(), std::declval<const T&>()))>>>
    : std::true_type {};

template <typename T>
inline constexpr bool has_absl_stringify_v = HasAbslStringify<T>::value;

using RawSink = absl::FormatRawSink;

enum class PrintMode { kHumanReadable, kSourceCode };

// Invokes PrintCorpusValue or PrintUserValue from the domain's type printer,
// depending on what's available.
// It will automatically call GetValue if needed for the PrintUserValue call. It
// simplifies as few of the Print implementations.
template <typename Domain>
void PrintValue(const Domain& domain, const corpus_type_t<Domain>& corpus_value,
                RawSink out, PrintMode mode) {
  auto printer = domain.GetPrinter();
  if constexpr (Requires<decltype(printer)>(
                    [&](auto t) -> decltype(t.PrintCorpusValue(
                                    corpus_value, out, mode)) {})) {
    printer.PrintCorpusValue(corpus_value, out, mode);
  } else {
    printer.PrintUserValue(domain.GetValue(corpus_value), out, mode);
  }
}

struct IntegralPrinter {
  template <typename T>
  void PrintUserValue(T v, RawSink out, PrintMode mode) const {
    if constexpr (std::is_enum_v<T>) {
      // TODO(sbenzaquen): Try to use enum labels where possible.
      // Use static_cast<> when printing source code to avoid init conversion.
      switch (mode) {
        case PrintMode::kHumanReadable:
          absl::Format(out, "%s{", GetTypeName<T>());
          break;
        case PrintMode::kSourceCode:
          absl::Format(out, "static_cast<%s>(", GetTypeName<T>());
          break;
      }
      PrintUserValue(static_cast<std::underlying_type_t<T>>(v), out, mode);
      switch (mode) {
        case PrintMode::kHumanReadable:
          absl::Format(out, "}");
          break;
        case PrintMode::kSourceCode:
          absl::Format(out, ")");
          break;
      }
    } else if constexpr (std::is_signed_v<T>) {
      PrintUserValue(static_cast<int64_t>(v), out, mode);
    } else {
      PrintUserValue(static_cast<uint64_t>(v), out, mode);
    }
  }

  void PrintUserValue(bool v, RawSink out, PrintMode mode) const;
  void PrintUserValue(char v, RawSink out, PrintMode mode) const;
  void PrintUserValue(uint64_t v, RawSink out, PrintMode mode) const;
  void PrintUserValue(int64_t v, RawSink out, PrintMode mode) const;
};

struct FloatingPrinter {
  void PrintUserValue(float v, RawSink out, PrintMode mode) const;
  void PrintUserValue(double v, RawSink out, PrintMode mode) const;
  void PrintUserValue(long double v, RawSink out, PrintMode mode) const;
};

struct StringPrinter {
  template <typename T>
  void PrintUserValue(const T& v, RawSink out, PrintMode mode) const {
    switch (mode) {
      case PrintMode::kHumanReadable:
        absl::Format(out, "\"");
        for (char c : v) {
          if (std::isprint(c)) {
            absl::Format(out, "%c", c);
          } else {
            absl::Format(out, "\\%03o", c);
          }
        }
        absl::Format(out, "\"");
        break;
      case PrintMode::kSourceCode: {
        // Make sure to properly C-escape strings when printing source code, and
        // explicitly construct a std::string of the right length if there is an
        // embedded NULL character.
        const absl::string_view input(v.data(), v.size());
        const std::string escaped = absl::CEscape(input);
        if (absl::StrContains(input, '\0')) {
          absl::Format(out, "std::string(\"%s\", %d)", escaped, v.size());
        } else {
          absl::Format(out, "\"%s\"", escaped);
        }
        break;
      }
    }
  }
};

template <typename... Inner>
struct AggregatePrinter {
  const std::tuple<Inner...>& inner;

  template <typename T>
  void PrintCorpusValue(const T& v, RawSink out, PrintMode mode) const {
    auto bound = internal::BindAggregate(
        v, std::integral_constant<int, sizeof...(Inner)>{});

    const auto print_one = [&](auto I) {
      if (I > 0) absl::Format(out, ", ");
      PrintValue(std::get<I>(inner), std::get<I>(bound), out, mode);
    };
    absl::Format(out, "{");
    ApplyIndex<sizeof...(Inner)>([&](auto... Is) { (print_one(Is), ...); });
    absl::Format(out, "}");
  }
};

template <typename... Inner>
struct VariantPrinter {
  const std::tuple<Inner...>& inner;

  template <typename T>
  void PrintCorpusValue(const T& v, RawSink out, PrintMode mode) const {
    if (mode == PrintMode::kHumanReadable) {
      absl::Format(out, "(index=%d, value=", v.index());
    }
    // The source code version will work as long as the types are unambiguous.
    // Printing the whole variant type to call the explicit constructor might be
    // an issue.
    Switch<sizeof...(Inner)>(v.index(), [&](auto I) {
      PrintValue(std::get<I>(inner), std::get<I>(v), out, mode);
    });
    if (mode == PrintMode::kHumanReadable) {
      absl::Format(out, ")");
    }
  }
};

template <typename... Inner>
struct OneOfPrinter {
  const std::tuple<Inner...>& inner;

  template <typename T>
  void PrintCorpusValue(const T& v, RawSink out, PrintMode mode) const {
    Switch<sizeof...(Inner)>(v.index(), [&](auto I) {
      PrintValue(std::get<I>(inner), std::get<I>(v), out, mode);
    });
  }
};

template <typename Domain, typename Inner>
struct OptionalPrinter {
  const Domain& domain;
  const Inner& inner_domain;

  void PrintCorpusValue(const corpus_type_t<Domain>& v, RawSink out,
                        PrintMode mode) const {
    using value_type = value_type_t<Domain>;
    constexpr bool is_pointer = Requires<value_type>(
        [](auto probe)
            -> std::enable_if_t<std::is_pointer_v<decltype(probe.get())>> {});
    if (v.index() == 1) {
      switch (mode) {
        case PrintMode::kHumanReadable:
          absl::Format(out, "(");
          PrintValue(inner_domain, std::get<1>(v), out, mode);
          absl::Format(out, ")");
          break;
        case PrintMode::kSourceCode: {
          // The source code version will work as long as the expression is
          // unambiguous.
          if constexpr (is_pointer) {
            std::string_view maker =
                is_unique_ptr_v<value_type>   ? "std::make_unique"
                : is_shared_ptr_v<value_type> ? "std::make_shared"
                                              : "<MAKE_SMART_POINTER>";
            absl::Format(out, "%s<%s>(", maker,
                         GetTypeName<typename value_type::element_type>());
          }
          PrintValue(inner_domain, std::get<1>(v), out, mode);
          if (is_pointer) absl::Format(out, ")");
          break;
        }
      }
    } else {
      if (is_pointer) {
        absl::Format(out, "%s", "nullptr");
      } else {
        auto type_name = GetTypeName<value_type>();
        size_t pos = type_name.find("::");
        if (pos != type_name.npos) {
          type_name = type_name.substr(0, pos + 2);
        }

        if (type_name == "std::" || type_name == "absl::") {
          absl::Format(out, "%s", type_name);
        }

        absl::Format(out, "%s", "nullopt");
      }
    }
  }
};

struct ProtobufPrinter {
  template <typename T>
  void PrintUserValue(const T& val, RawSink out, PrintMode mode) const {
    if constexpr (Requires<T>([](auto v) -> decltype(*v) {})) {
      // Deref if necessary.
      return PrintUserValue(*val, out, mode);
    } else {
      switch (mode) {
        case PrintMode::kHumanReadable:
          absl::Format(out, "(%s)", val.ShortDebugString());
          break;
        case PrintMode::kSourceCode:
          absl::Format(out, "ParseTestProto(R\"pb(%s)pb\")",
                       val.ShortDebugString());
          break;
      }
    }
  }
};

template <typename D>
struct ProtobufEnumPrinter {
  D descriptor;

  template <typename T>
  void PrintUserValue(const T& v, RawSink out, PrintMode mode) const {
    if (auto vd = descriptor->FindValueByNumber(v); vd != nullptr) {
      // For enums nested inside a message, protoc generates an enum named
      // `<MessageName>_<EnumName>` and aliases for each label of the form
      // `<MessageName>::<LabelN>`, so we can strip the trailing `_<EnumName>`
      // and append `::<Label>`.
      //
      // For top-level enums in C++11, the enumerators are local to the enum,
      // so leave the name untouched to print `<Enum>::<Label>`.
      absl::string_view type_name = GetTypeName<T>();
      const std::string& enum_name = descriptor->name();
      if (absl::EndsWith(type_name, "_" + enum_name)) {
        type_name.remove_suffix(enum_name.size() + 1);
      }
      absl::Format(out, "%s::%s", type_name, vd->name());
      if (mode == PrintMode::kHumanReadable) {
        absl::Format(out, " (");
        IntegralPrinter{}.PrintUserValue(static_cast<int64_t>(v), out, mode);
        absl::Format(out, ")");
      }
      return;
    }
    // Fall back on regular enum printer.
    IntegralPrinter{}.PrintUserValue(v, out, mode);
  }
};

struct MonostatePrinter {
  template <typename T>
  void PrintUserValue(const T&, RawSink out, PrintMode) const {
    absl::Format(out, "{}");
  }
};

template <typename Domain, typename Inner>
struct ContainerPrinter {
  const Inner& inner_domain;

  void PrintCorpusValue(const corpus_type_t<Domain>& val, RawSink out,
                        PrintMode mode) const {
    absl::Format(out, "{");
    bool first = true;
    for (const auto& v : val) {
      if (!first) absl::Format(out, ", ");
      first = false;
      PrintValue(inner_domain, v, out, mode);
    }
    absl::Format(out, "}");
  }
};

template <typename F>
constexpr bool HasFunctionName() {
  return std::is_function_v<std::remove_pointer_t<F>>;
}

template <typename F>
std::string GetFunctionName(const F& f, absl::string_view default_name) {
  if constexpr (HasFunctionName<F>()) {
    char buffer[1024];
    if (absl::Symbolize(reinterpret_cast<const void*>(f), buffer,
                        sizeof(buffer))) {
      absl::string_view v = buffer;
      absl::ConsumeSuffix(&v, "()");
      SkipAnonymous(v);
      return std::string(v);
    }
  }
  return std::string(default_name);
}

template <typename Mapper, typename... Inner>
struct MappedPrinter {
  const Mapper& mapper;
  const std::tuple<Inner...>& inner;
  absl::string_view map_fn_name;

  template <typename CorpusT>
  void PrintCorpusValue(const CorpusT& corpus_value, RawSink out,
                        PrintMode mode) const {
    auto value = ApplyIndex<sizeof...(Inner)>([&](auto... I) {
      return mapper(std::get<I>(inner).GetValue(std::get<I>(corpus_value))...);
    });

    switch (mode) {
      case PrintMode::kHumanReadable: {
        // In human readable mode we try and print the user value.
        AutodetectTypePrinter<decltype(value)>().PrintUserValue(value, out,
                                                                mode);
        break;
      }
      case PrintMode::kSourceCode:
        if constexpr (!HasFunctionName<Mapper>() &&
                      HasKnownPrinter<decltype(value)>()) {
          if (map_fn_name.empty()) {
            // Fall back on printing the user value if the mapping function is
            // unknown (e.g. a lambda) and the value has a useful printer.
            AutodetectTypePrinter<decltype(value)>().PrintUserValue(value, out,
                                                                    mode);
            break;
          }
        }

        // In source code mode we print the mapping expression.
        // This should give a better chance of valid code, given that the result
        // of the mapping function can easily be a user defined type we can't
        // generate otherwise.
        absl::string_view default_name =
            map_fn_name.empty() ? "<MAPPING_FUNCTION>" : map_fn_name;
        absl::Format(out, "%s(", GetFunctionName(mapper, default_name));
        const auto print_one = [&](auto I) {
          if (I != 0) absl::Format(out, ", ");
          PrintValue(std::get<I>(inner), std::get<I>(corpus_value), out, mode);
        };
        ApplyIndex<sizeof...(Inner)>([&](auto... Is) { (print_one(Is), ...); });
        absl::Format(out, ")");
    }
  }
};

template <typename FlatMapper, typename... Inner>
struct FlatMappedPrinter {
  const FlatMapper& mapper;
  const std::tuple<Inner...>& inner;

  template <typename CorpusT>
  void PrintCorpusValue(const CorpusT& corpus_value, RawSink out,
                        PrintMode mode) const {
    auto output_domain = ApplyIndex<sizeof...(Inner)>([&](auto... I) {
      return mapper(
          // the first field of `corpus_value` is the output value, so skip it
          std::get<I>(inner).GetValue(std::get<I + 1>(corpus_value))...);
    });

    switch (mode) {
      case PrintMode::kHumanReadable: {
        // Delegate to the output domain's printer.
        PrintValue(output_domain, std::get<0>(corpus_value), out, mode);
        break;
      }
      case PrintMode::kSourceCode:
        if constexpr (!HasFunctionName<FlatMapper>()) {
          PrintValue(output_domain, std::get<0>(corpus_value), out, mode);
          break;
        }

        // In source code mode we print the mapping expression.
        // This should give a better chance of valid code, given that the result
        // of the mapping function can easily be a user defined type we can't
        // generate otherwise.
        absl::Format(out, "%s(",
                     GetFunctionName(mapper, "<FLAT_MAP_FUNCTION>"));
        const auto print_one = [&](auto I) {
          if (I != 0) absl::Format(out, ", ");
          PrintValue(std::get<I>(inner), std::get<I + 1>(corpus_value), out,
                     mode);
        };
        ApplyIndex<sizeof...(Inner)>([&](auto... Is) { (print_one(Is), ...); });
        absl::Format(out, ")");
    }
  }
};

struct AutodetectAggregatePrinter {
  template <typename T>
  void PrintUserValue(const T& v, RawSink out, PrintMode mode) {
    if (mode == PrintMode::kHumanReadable) {
      // In human-readable mode, prefer formatting with Abseil if possible.
      if constexpr (has_absl_stringify_v<T>) {
        absl::Format(out, "%v", v);
        return;
      }
    }
    std::tuple bound = DetectBindAggregate(v);
    const auto print_one = [&](auto I) {
      if (I > 0) absl::Format(out, ", ");
      AutodetectTypePrinter<
          std::remove_reference_t<std::tuple_element_t<I, decltype(bound)>>>()
          .PrintUserValue(std::get<I>(bound), out, mode);
    };
    absl::Format(out, "{");
    ApplyIndex<std::tuple_size_v<decltype(bound)>>(
        [&](auto... Is) { (print_one(Is), ...); });
    absl::Format(out, "}");
  }
};

struct DurationPrinter {
  void PrintUserValue(const absl::Duration duration, RawSink out,
                      PrintMode mode) {
    switch (mode) {
      case PrintMode::kHumanReadable:
        absl::Format(out, "%s", absl::FormatDuration(duration));
        break;
      case PrintMode::kSourceCode:
        if (duration == absl::InfiniteDuration()) {
          absl::Format(out, "absl::InfiniteDuration()");
        } else if (duration == -absl::InfiniteDuration()) {
          absl::Format(out, "-absl::InfiniteDuration()");
        } else if (duration == absl::ZeroDuration()) {
          absl::Format(out, "absl::ZeroDuration()");
        } else {
          uint32_t ticks = GetTicks(duration);
          int64_t secs = GetSeconds(duration);
          if (ticks == 0) {
            absl::Format(out, "absl::Seconds(%d)", secs);
          } else if (ticks % 4 == 0) {
            absl::Format(out, "absl::Seconds(%d) + absl::Nanoseconds(%u)", secs,
                         ticks / 4);
          } else {
            absl::Format(out,
                         "absl::Seconds(%d) + (absl::Nanoseconds(1) / 4) * %u",
                         secs, ticks);
          }
        }
        break;
    }
  }
};

struct TimePrinter {
  void PrintUserValue(const absl::Time time, RawSink out, PrintMode mode) {
    switch (mode) {
      case PrintMode::kHumanReadable:
        absl::Format(out, "%s", absl::FormatTime(time, absl::UTCTimeZone()));
        break;
      case PrintMode::kSourceCode:
        if (time == absl::InfinitePast()) {
          absl::Format(out, "absl::InfinitePast()");
        } else if (time == absl::InfiniteFuture()) {
          absl::Format(out, "absl::InfiniteFuture()");
        } else if (time == absl::UnixEpoch()) {
          absl::Format(out, "absl::UnixEpoch()");
        } else {
          absl::Format(out, "absl::UnixEpoch() + ");
          DurationPrinter{}.PrintUserValue(time - absl::UnixEpoch(), out, mode);
        }
        break;
    }
  }
};

struct UnknownPrinter {
  template <typename T>
  void PrintUserValue(const T& v, RawSink out, PrintMode mode) {
    if (mode == PrintMode::kHumanReadable) {
      // Try formatting with Abseil. We can't guarantee a good source code
      // result, but it should be ok for human readable.
      if constexpr (has_absl_stringify_v<T>) {
        absl::Format(out, "%v", v);
        return;
      }
      // Some standard types have operator<<.
      if constexpr (std::is_scalar_v<T> || is_std_complex_v<T>) {
        absl::Format(out, "%s", absl::FormatStreamed(v));
        return;
      }
    }
    absl::Format(out, "<unprintable value>");
  }
};

template <typename T>
decltype(auto) AutodetectTypePrinter() {
  if constexpr (std::numeric_limits<T>::is_integer || std::is_enum_v<T>) {
    return IntegralPrinter{};
  } else if constexpr (std::is_floating_point_v<T>) {
    return FloatingPrinter{};
  } else if constexpr (std::is_convertible_v<T, absl::string_view> ||
                       std::is_convertible_v<T, std::string_view>) {
    return StringPrinter{};
  } else if constexpr (is_monostate_v<T>) {
    return MonostatePrinter{};
  } else if constexpr (is_protocol_buffer_v<T>) {
    return ProtobufPrinter{};
  } else if constexpr (is_bindable_aggregate_v<T>) {
    return AutodetectAggregatePrinter{};
  } else if constexpr (std::is_same_v<T, absl::Duration>) {
    return DurationPrinter{};
  } else if constexpr (std::is_same_v<T, absl::Time>) {
    return TimePrinter{};
  } else {
    return UnknownPrinter{};
  }
}

template <typename T>
constexpr bool HasKnownPrinter() {
  return !std::is_convertible_v<decltype(AutodetectTypePrinter<T>()),
                                UnknownPrinter>;
}

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_TYPE_SUPPORT_H_
