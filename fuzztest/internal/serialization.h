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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_SERIALIZATION_H_
#define FUZZTEST_FUZZTEST_INTERNAL_SERIALIZATION_H_

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "absl/numeric/int128.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "absl/types/variant.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/meta.h"

namespace fuzztest::internal {

struct IRObject;

// Simple intermediate representation object and ParseInput/SerializeInput
// functions for it.
//
// The serialization format follows the Text format for Protocol Buffers of the
// `IRObject` message, with the following message definition:
//
// message IRObject {
//   oneof value {
//     uint64 i = 1;
//     double d = 2;
//     bytes s = 3;
//   }
//   repeated IRObject sub = 4;
// }
//
// The protobuf definition does not allow putting `sub` in the oneof because it
// is repeated, but the C++ type enforces the invariant that only one field is
// set.

struct IRObject {
  using Value = absl::variant<std::monostate, uint64_t, double, std::string,
                              std::vector<IRObject>>;
  Value value;

  IRObject() = default;
  template <
      typename T,
      std::enable_if_t<std::is_enum_v<T> || std::is_integral_v<T>, int> = 0>
  explicit IRObject(T v) : value(static_cast<uint64_t>(v)) {}
  template <typename T, std::enable_if_t<std::is_floating_point_v<T>, int> = 0>
  explicit IRObject(T v) : value(static_cast<double>(v)) {}
  explicit IRObject(Value v) : value(std::move(v)) {}

  // Accessors for scalars to simplify their use, and hide conversions when
  // needed.
  // Returns optional<T>, except when T is std::string it returns
  // std::optional<std::string_view> to avoid a copy.
  template <typename T>
  auto GetScalar() const {
    if constexpr (std::is_enum_v<T>) {
      auto inner = GetScalar<std::underlying_type_t<T>>();
      return inner ? std::optional(static_cast<T>(*inner)) : std::nullopt;
    } else if constexpr (std::is_integral_v<T>) {
      const uint64_t* i = absl::get_if<uint64_t>(&value);
      return i != nullptr ? std::optional(static_cast<T>(*i)) : std::nullopt;
    } else if constexpr (std::is_same_v<float, T> ||
                         std::is_same_v<double, T>) {
      const double* i = absl::get_if<double>(&value);
      return i != nullptr ? std::optional(static_cast<T>(*i)) : std::nullopt;
    } else if constexpr (std::is_same_v<std::string, T>) {
      std::optional<std::string_view> out;
      if (const auto* s = absl::get_if<std::string>(&value)) {
        out = *s;
      }
      return out;
    }
  }

  // Set the value of the node to `v`. The function will promote the input to
  // the types supported in the variant.
  // Overwrites any existing data.
  template <typename T>
  void SetScalar(T v) {
    if constexpr (std::is_enum_v<T>) {
      SetScalar(static_cast<std::underlying_type_t<T>>(v));
    } else if constexpr (std::is_integral_v<T>) {
      value = static_cast<uint64_t>(v);
    } else if constexpr (std::is_same_v<float, T> ||
                         std::is_same_v<double, T>) {
      value = static_cast<double>(v);
    } else if constexpr (std::is_same_v<std::string, T>) {
      value = std::move(v);
    } else {
      static_assert(always_false<T>, "Invalid type");
    }
  }

  // If this node contains subs, return it as a Span. Otherwise, nullopt.
  std::optional<absl::Span<const IRObject>> Subs() const {
    if (const auto* i = absl::get_if<std::vector<IRObject>>(&value)) {
      return *i;
    }
    // The empty vector is serialized the same way as the monostate: nothing.
    // Handle that case too.
    if (absl::holds_alternative<std::monostate>(value)) {
      return absl::Span<const IRObject>{};
    }
    return std::nullopt;
  }

  // Set this node to contain subs, and return a reference to the vector of
  // them.
  // Overwrites any existing data.
  std::vector<IRObject>& MutableSubs() {
    if (!absl::holds_alternative<std::vector<IRObject>>(value)) {
      value.emplace<std::vector<IRObject>>();
    }
    return absl::get<std::vector<IRObject>>(value);
  }

  // Conversion functions to map IRObject to/from corpus values.
  // Corpus types have restrictions.
  // They must be one of:
  //  - A scalar (integer, floating, string).
  //  - A dynamic container (eg std::vector), where the inner type is also
  //    supported.
  //  - A tuple-like, where the inner types are supported.
  //  - A std::variant, where the inner types are supported.
  //  - A monostate object.
  //  - A protobuf message object.
  //  - An IRObject itself.
  template <typename T>
  static IRObject FromCorpus(const T& value) {
    if constexpr (is_monostate_v<T>) {
      return {};
    } else if constexpr (std::is_constructible_v<IRObject, T>) {
      return IRObject(value);
    } else if constexpr (is_variant_v<T>) {
      IRObject obj;
      auto& v = obj.MutableSubs();
      v.emplace_back(value.index());
      v.push_back(
          std::visit([](const auto& v) { return FromCorpus(v); }, value));
      return obj;
    } else if constexpr (std::is_same_v<T, absl::int128> ||
                         std::is_same_v<T, absl::uint128>) {
      return FromCorpus(
          std::pair(absl::Uint128High64(value), absl::Uint128Low64(value)));
    } else if constexpr (is_protocol_buffer_v<T>) {
      return IRObject(value.SerializeAsString());
    } else if constexpr (is_bitvector_v<T>) {
      IRObject obj;
      auto& v = obj.MutableSubs();
      // Force conversion to bool. The `is_dynamic_container_v` case allows elem
      // to keep the bit iterator type, which IRObject doesn't understand.
      for (bool elem : value) {
        v.push_back(IRObject(elem));
      }
      return obj;
    } else if constexpr (is_dynamic_container_v<T>) {
      IRObject obj;
      auto& v = obj.MutableSubs();
      for (const auto& elem : value) {
        v.push_back(FromCorpus(elem));
      }
      return obj;
    } else {
      // Must be a tuple like object.
      return std::apply(
          [](const auto&... elem) {
            IRObject obj;
            auto& v = obj.MutableSubs();
            (v.push_back(FromCorpus(elem)), ...);
            return obj;
          },
          value);
    }
  }

  template <typename T>
  std::optional<T> ToCorpus() const {
    if constexpr (std::is_const_v<T>) {
      return ToCorpus<std::remove_const_t<T>>();
    } else if constexpr (is_monostate_v<T>) {
      if (absl::holds_alternative<std::monostate>(value)) return T{};
      return std::nullopt;
    } else if constexpr (std::is_same_v<T, IRObject>) {
      return *this;
    } else if constexpr (std::is_constructible_v<IRObject, T>) {
      if (auto v = GetScalar<T>()) {
        return static_cast<T>(*v);
      }
      return std::nullopt;
    } else if constexpr (is_variant_v<T>) {
      auto elems = Subs();
      if (!elems || elems->size() != 2) return std::nullopt;
      auto index = (*elems)[0].ToCorpus<size_t>();
      if (!index || *index >= std::variant_size_v<T>) return std::nullopt;
      return Switch<std::variant_size_v<T>>(
          *index, [&](auto I) -> std::optional<T> {
            auto inner =
                (*elems)[1].ToCorpus<std::variant_alternative_t<I, T>>();
            if (inner) return T(std::in_place_index<I>, *std::move(inner));
            return std::nullopt;
          });
    } else if constexpr (std::is_same_v<T, absl::int128> ||
                         std::is_same_v<T, absl::uint128>) {
      if (auto res = ToCorpus<std::pair<uint64_t, uint64_t>>()) {
        return static_cast<T>(absl::MakeUint128(res->first, res->second));
      }
      return std::nullopt;
    } else if constexpr (is_protocol_buffer_v<T>) {
      const std::string* v = absl::get_if<std::string>(&value);
      T out;
      if (v && out.ParseFromString(*v)) return out;
      return std::nullopt;
    } else if constexpr (is_dynamic_container_v<T>) {
      auto elems = Subs();
      if (!elems) return std::nullopt;

      T out;
      for (const auto& elem : *elems) {
        if (auto inner = elem.ToCorpus<typename T::value_type>()) {
          out.insert(out.end(), *std::move(inner));
        } else {
          return std::nullopt;
        }
      }
      return out;
    } else {
      // Must be a tuple like object.
      auto elems = Subs();
      if (!elems || elems->size() != std::tuple_size_v<T>) return std::nullopt;
      auto it = elems->begin();
      auto parts = ApplyIndex<std::tuple_size_v<T>>([&](auto... I) {
        return std::tuple{it++->ToCorpus<std::tuple_element_t<I, T>>()...};
      });
      return std::apply(
          [&](auto&... part) -> std::optional<T> {
            if ((!part || ...)) return std::nullopt;
            return T{*std::move(part)...};
          },
          parts);
    }
  }

  static constexpr std::string_view kHeader = "FUZZTESTv1";

  absl::string_view AsAbsl(std::string_view str) const {
    return {str.data(), str.size()};
  }

  // Serialize the object as a string. This is used to persist the object on
  // files for reproducing bugs later.
  template <typename ValueType>
  std::string ToString() const {
    // Return single string-like or proto values as raw strings.
    if constexpr (std::is_same_v<ValueType, std::string> ||
                  is_protocol_buffer_v<ValueType>) {
      FUZZTEST_INTERNAL_CHECK_PRECONDITION(
          absl::holds_alternative<std::string>(value),
          "String-like value should hold a string!");
      return absl::get<std::string>(value);
    }
    std::string out = absl::StrCat(AsAbsl(kHeader), "\n");
    // Construct out using IRObject format.
    IRObject::Visit(out);
    return out;
  }

  template <typename ValueType>
  std::optional<IRObject> FromString(std::string_view str) {
    IRObject object;
    if constexpr (std::is_same_v<ValueType, std::string>) {
      object.value.emplace<std::string>(str);
      FUZZTEST_INTERNAL_CHECK(
          absl::holds_alternative<std::string>(object.value),
          "IRObject value should hold a string after deserializing from a "
          "single string-like value!");
      return object;
    }
    if (ReadToken(str) != kHeader) return std::nullopt;
    if (!ParseImpl(object, str) || !ReadToken(str).empty()) return std::nullopt;
    return object;
  }

 private:
  template <typename T>
  static T RemoveConstFromPair(T);

  template <typename K, typename V>
  static std::pair<std::remove_const_t<K>, std::remove_const_t<V>>
      RemoveConstFromPair(std::pair<K, V>);

  void Visit(std::string& out) const;
  std::string_view ReadToken(std::string_view& in) const;
  bool ParseImpl(IRObject& obj, std::string_view& str);
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_SERIALIZATION_H_
