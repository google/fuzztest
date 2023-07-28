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

#include "./fuzztest/internal/serialization.h"

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"

namespace fuzztest::internal {

namespace {

struct OutputVisitor {
  size_t index;
  int indent;
  std::string& out;

  void operator()(std::monostate) const {}

  void operator()(uint64_t value) const { absl::StrAppend(&out, "i: ", value); }

  void operator()(double value) const {
    // Print with the maximum precision necessary to prevent losses.
    absl::StrAppendFormat(&out, "d: %.*g",
                          std::numeric_limits<double>::max_digits10, value);
  }

  void operator()(const std::string& value) const {
    absl::StrAppend(&out, "s: \"");
    for (char c : value) {
      if (std::isprint(c) && c != '\\' && c != '"') {
        out.append(1, c);
      } else {
        absl::StrAppendFormat(&out, "\\%03o", c);
      }
    }
    absl::StrAppend(&out, "\"");
  }

  void operator()(const std::vector<IRObject>& value) const {
    for (const auto& sub : value) {
      const bool sub_is_scalar =
          !std::holds_alternative<std::vector<IRObject>>(sub.value);
      absl::StrAppendFormat(&out, "%*ssub {%s", indent, "",
                            sub_is_scalar ? " " : "\n");
      std::visit(OutputVisitor{sub.value.index(), indent + 2, out}, sub.value);
      absl::StrAppendFormat(&out, "%*s}\n", sub_is_scalar ? 0 : indent,
                            sub_is_scalar ? " " : "");
    }
  }
};

constexpr std::string_view kHeader = "FUZZTESTv1";

absl::string_view AsAbsl(std::string_view str) {
  return {str.data(), str.size()};
}

std::string_view ReadToken(std::string_view& in) {
  while (!in.empty() && std::isspace(in[0])) in.remove_prefix(1);
  if (in.empty()) return in;
  size_t end = 1;
  const auto is_literal = [](char c) {
    return std::isalnum(c) != 0 || c == '+' || c == '-' || c == '.';
  };
  if (is_literal(in[0])) {
    while (end < in.size() && is_literal(in[end])) ++end;
  } else if (in[0] == '"') {
    while (end < in.size() && in[end] != '"') ++end;
    if (end < in.size()) ++end;
  }
  std::string_view res = in.substr(0, end);
  in.remove_prefix(end);
  return res;
}

bool ReadScalar(uint64_t& out, std::string_view value) {
  return absl::SimpleAtoi(AsAbsl(value), &out);
}

bool ReadScalar(double& out, std::string_view value) {
  return absl::SimpleAtod(AsAbsl(value), &out);
}

bool ReadScalar(std::string& out, std::string_view value) {
  if (value.empty() || value[0] != '"') return false;
  value.remove_prefix(1);

  if (value.empty() || value.back() != '"') return false;
  value.remove_suffix(1);

  while (!value.empty()) {
    if (value[0] != '\\') {
      out += value[0];
      value.remove_prefix(1);
    } else {
      uint32_t v = 0;

      if (value.size() < 4) return false;
      for (int i = 1; i < 4; ++i) {
        if (value[i] < '0' || value[i] > '7') {
          return false;
        }
        v = 8 * v + value[i] - '0';
      }
      if (v > 255) return false;

      out += static_cast<char>(v);
      value.remove_prefix(4);
    }
  }
  return true;
}

bool ParseImpl(IRObject& obj, std::string_view& str) {
  std::string_view key = ReadToken(str);
  if (key.empty() || key == "}") {
    // The object is empty. Put the token back and return.
    str = std::string_view(key.data(), str.data() + str.size() - key.data());
    return true;
  }

  if (key == "sub") {
    auto& v = obj.value.emplace<std::vector<IRObject>>();
    do {
      if (ReadToken(str) != "{") return false;
      if (!ParseImpl(v.emplace_back(), str)) return false;
      if (ReadToken(str) != "}") return false;
      key = ReadToken(str);
    } while (key == "sub");
    // We are done reading this repeated sub.
    // Put the token back for the caller.
    str = std::string_view(key.data(), str.data() + str.size() - key.data());
    return true;
  } else {
    if (ReadToken(str) != ":") return false;
    auto value = ReadToken(str);
    auto& v = obj.value;
    if (key == "i") {
      return ReadScalar(v.emplace<uint64_t>(), value);
    } else if (key == "d") {
      return ReadScalar(v.emplace<double>(), value);
    } else if (key == "s") {
      return ReadScalar(v.emplace<std::string>(), value);
    } else {
      // Unrecognized key
      return false;
    }
  }
}

}  // namespace

std::string IRObject::ToString() const {
  std::string out = absl::StrCat(AsAbsl(kHeader), "\n");
  std::visit(OutputVisitor{value.index(), 0, out}, value);
  return out;
}

// TODO(lszekeres): Return StatusOr<IRObject>.
std::optional<IRObject> IRObject::FromString(std::string_view str) {
  IRObject object;
  if (ReadToken(str) != kHeader) return std::nullopt;
  if (!ParseImpl(object, str) || !ReadToken(str).empty()) return std::nullopt;
  return object;
}

}  // namespace fuzztest::internal
