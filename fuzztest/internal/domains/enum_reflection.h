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

#include <array>
#include <cstddef>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"

namespace fuzztest::internal {

namespace enum_reflection {

constexpr bool IsValidCharacter(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') ||
         (c >= 'A' && c <= 'Z') || c == '_';
}

constexpr bool IsNumber(char c) { return c >= '0' && c <= '9'; }

// When the template parameter V is equal to a valid enum value,
// clang replaces __PRETTY_FUNCTION__ with a string ending in something like:
// "[E = my_namespace::MyEnum, V = my_namespace::MyEnum::kRed]"
// If V is not a valid value, the suffix looks like:
// "[E = my_namespace::MyEnum, V = (my_namespace::MyEnum)5]".
constexpr bool IsValidEnumValueSuffix(absl::string_view name) {
  if (name.empty() || name.back() != ']') return false;
  name.remove_suffix(1);

  size_t i = name.size();
  while (i > 0 && IsValidCharacter(name[i - 1])) {
    --i;
  }
  return i < name.size() && !IsNumber(name[i]);
}

template <typename E, E V>
constexpr bool IsValidEnumValue() {
#if defined(__clang__) || defined(__GNUC__)
  return IsValidEnumValueSuffix(
      {__PRETTY_FUNCTION__, sizeof(__PRETTY_FUNCTION__) - 1});
#else
#error "Enum reflection is only supported on Clang and GCC"
#endif
}

template <typename E, int... Is>
std::vector<E> GetValidEnumValues(std::integer_sequence<int, Is...>) {
  constexpr auto is_valid =
      std::array{IsValidEnumValue<E, static_cast<E>(Is - 128)>()...};
  constexpr auto values_arr = std::array{static_cast<E>(Is - 128)...};

  std::vector<E> values;
  for (size_t i = 0; i < sizeof...(Is); ++i) {
    if (is_valid[i]) {
      values.push_back(values_arr[i]);
    }
  }
  return values;
}

// Currently only available with Clang and GCC.
// Assumes that the enums values are within the range [-128, 127].
template <typename E>
std::vector<E> GetEnumValues() {
  return GetValidEnumValues<E>(std::make_integer_sequence<int, 256>{});
}

}  // namespace enum_reflection

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_DOMAINS_ENUM_REFLECTION_H_
