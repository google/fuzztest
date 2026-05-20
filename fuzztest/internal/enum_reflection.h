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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ENUM_REFLECTION_H_
#define FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ENUM_REFLECTION_H_

#include <cstddef>
#include <vector>

#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "./fuzztest/internal/meta.h"

namespace fuzztest::internal::enum_reflection {

constexpr bool IsValidCharacter(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
         (c >= 'A' && c <= 'Z') || c == '_';
}

constexpr bool IsDigit(char c) { return c >= '0' && c <= '9'; }

// Checks if `name` ends with `compiler_suffix`. After removing it, checks if
// the remaining string ends with a valid identifier (valid enum value) rather
// than a numeric literal (invalid value).
constexpr bool IsValidEnumValueSuffix(absl::string_view name,
                                      absl::string_view compiler_suffix) {
  if (!absl::ConsumeSuffix(&name, compiler_suffix)) return false;

  size_t i = name.size();
  while (i > 0 && IsValidCharacter(name[i - 1])) {
    --i;
  }
  return i < name.size() && !IsDigit(name[i]);
}

// When the template parameter V is equal to a valid enum value,
// compilers replace the signature macro with a string containing the enum name.
//
// For Clang/GCC, __PRETTY_FUNCTION__ ends in something like:
// "[E = ns::MyEnum, V = ns::MyEnum::kRed]"
// If V is not a valid value, the suffix looks like:
// "[E = ns::MyEnum, V = (ns::MyEnum)5]".
//
// For MSVC, __FUNCSIG__ ends in something like:
// "IsValidEnumValue<enum ns::MyEnum,ns::MyEnum::kRed>(void)"
// If V is not a valid value, it looks like:
// "IsValidEnumValue<enum ns::MyEnum,5>(void)"
template <typename E, E V>
constexpr bool IsValidEnumValue() {
#if defined(__clang__) || defined(__GNUC__)
  constexpr absl::string_view kCompilerSuffix = "]";
  return IsValidEnumValueSuffix(
      {__PRETTY_FUNCTION__, sizeof(__PRETTY_FUNCTION__) - 1}, kCompilerSuffix);
#elif defined(_MSC_VER)
  constexpr absl::string_view kCompilerSuffix = ">(void)";
  return IsValidEnumValueSuffix({__FUNCSIG__, sizeof(__FUNCSIG__) - 1},
                                kCompilerSuffix);
#else
#error "Enum reflection is only supported on Clang, GCC, and MSVC"
#endif
}

template <typename E>
constexpr bool HasEnumValuesInRange() {
  return ApplyIndex<256>([](auto... I) {
    return (IsValidEnumValue<E, static_cast<E>(static_cast<int>(I) - 128)>() ||
            ...);
  });
}

// Currently only available with Clang, GCC and MSVC.
// Assumes that the enums values are within the range [-128, 127].
template <typename E>
std::vector<E> GetEnumValues() {
  return ApplyIndex<256>([](auto... I) {
    std::vector<E> values;
    auto add_if_valid = [&](auto index) {
      if constexpr (IsValidEnumValue<E, static_cast<E>(static_cast<int>(index) -
                                                       128)>()) {
        values.push_back(static_cast<E>(static_cast<int>(index) - 128));
      }
    };
    (add_if_valid(I), ...);
    return values;
  });
}

}  // namespace fuzztest::internal::enum_reflection

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ENUM_REFLECTION_H_
