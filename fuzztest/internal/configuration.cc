// Copyright 2023 Google LLC
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

#include "./fuzztest/internal/configuration.h"

#include <cstddef>
#include <cstring>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>

#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"

namespace fuzztest::internal {
namespace {

template <typename T>
size_t SpaceFor(const T&) {
  return sizeof(T);
}

template <>
size_t SpaceFor(const absl::string_view& str) {
  return SpaceFor(str.size()) + str.size();
}

template <>
size_t SpaceFor(const std::string& str) {
  return SpaceFor(absl::string_view(str));
}

template <>
size_t SpaceFor(const std::optional<std::string>& obj) {
  return SpaceFor(obj.has_value()) + (obj.has_value() ? SpaceFor(*obj) : 0);
}

template <int&... ExplicitArgumentBarrier, typename IntT,
          typename = std::enable_if_t<std::is_integral_v<IntT>>>
size_t WriteIntegral(std::string& out, size_t offset, IntT val) {
  CHECK_GE(out.size(), offset + SpaceFor(val));
  std::memcpy(out.data() + offset, &val, SpaceFor(val));
  offset += SpaceFor(val);
  return offset;
}

size_t WriteString(std::string& out, size_t offset, absl::string_view str) {
  CHECK_GE(out.size(), offset + SpaceFor(str));
  offset = WriteIntegral(out, offset, str.size());
  std::memcpy(out.data() + offset, str.data(), str.size());
  offset += str.size();
  return offset;
}

size_t WriteOptionalString(std::string& out, size_t offset,
                           const std::optional<std::string>& str) {
  CHECK_GE(out.size(), offset + SpaceFor(str));
  offset = WriteIntegral(out, offset, str.has_value());
  if (str.has_value()) {
    offset = WriteString(out, offset, *str);
  }
  return offset;
}

#define ASSIGN_OR_RETURN(var, expr)              \
  auto var = expr;                               \
  if (!var.ok()) return std::move(var).status(); \
  static_assert(true, "")  // Swallow semicolon

template <typename IntT, int&... ExplicitArgumentBarrier,
          typename = std::enable_if_t<std::is_integral_v<IntT>>>
absl::StatusOr<IntT> Consume(absl::string_view& buffer) {
  IntT val = 0;
  if (buffer.size() < SpaceFor(val)) {
    return absl::InvalidArgumentError(
        "Couldn't consume a value from a buffer.");
  }
  std::memcpy(&val, buffer.data(), SpaceFor(val));
  buffer.remove_prefix(SpaceFor(val));
  return val;
}

absl::StatusOr<std::string> ConsumeString(absl::string_view& buffer) {
  ASSIGN_OR_RETURN(size, Consume<size_t>(buffer));
  if (buffer.size() < *size) {
    return absl::InvalidArgumentError(
        "Couldn't consume a value from a buffer.");
  }
  std::string str(buffer.data(), *size);
  buffer.remove_prefix(*size);
  return str;
}

absl::StatusOr<std::optional<std::string>> ConsumeOptionalString(
    absl::string_view& buffer) {
  ASSIGN_OR_RETURN(has_value, Consume<bool>(buffer));
  if (!*has_value) return std::nullopt;
  return ConsumeString(buffer);
}

}  // namespace

std::string Configuration::Serialize() const {
  std::string time_limit_per_input_str =
      absl::FormatDuration(time_limit_per_input);
  std::string out;
  out.resize(SpaceFor(corpus_database) + SpaceFor(binary_identifier) +
             SpaceFor(reproduce_findings_as_separate_tests) +
             SpaceFor(replay_coverage_inputs) + SpaceFor(stack_limit) +
             SpaceFor(rss_limit) + SpaceFor(time_limit_per_input_str) +
             SpaceFor(crashing_input_to_reproduce));
  size_t offset = 0;
  offset = WriteString(out, offset, corpus_database);
  offset = WriteString(out, offset, binary_identifier);
  offset = WriteIntegral(out, offset, reproduce_findings_as_separate_tests);
  offset = WriteIntegral(out, offset, replay_coverage_inputs);
  offset = WriteIntegral(out, offset, stack_limit);
  offset = WriteIntegral(out, offset, rss_limit);
  offset = WriteString(out, offset, time_limit_per_input_str);
  offset = WriteOptionalString(out, offset, crashing_input_to_reproduce);
  CHECK_EQ(offset, out.size());
  return out;
}

absl::StatusOr<Configuration> Configuration::Deserialize(
    absl::string_view serialized) {
  return [=]() mutable -> absl::StatusOr<Configuration> {
    ASSIGN_OR_RETURN(corpus_database, ConsumeString(serialized));
    ASSIGN_OR_RETURN(binary_identifier, ConsumeString(serialized));
    ASSIGN_OR_RETURN(reproduce_findings_as_separate_tests,
                     Consume<bool>(serialized));
    ASSIGN_OR_RETURN(replay_coverage_inputs, Consume<bool>(serialized));
    ASSIGN_OR_RETURN(stack_limit, Consume<size_t>(serialized));
    ASSIGN_OR_RETURN(rss_limit, Consume<size_t>(serialized));
    ASSIGN_OR_RETURN(time_limit_per_input_str, ConsumeString(serialized));
    ASSIGN_OR_RETURN(crashing_input_to_reproduce,
                     ConsumeOptionalString(serialized));
    if (!serialized.empty()) {
      return absl::InvalidArgumentError(
          "Buffer is not empty after consuming a serialized configuration.");
    }
    absl::Duration time_limit_per_input;
    if (!absl::ParseDuration(*time_limit_per_input_str,
                             &time_limit_per_input)) {
      return absl::InvalidArgumentError(absl::StrCat(
          "Couldn't parse a duration: ", *time_limit_per_input_str));
    }
    return Configuration{*std::move(corpus_database),
                         *std::move(binary_identifier),
                         *reproduce_findings_as_separate_tests,
                         *replay_coverage_inputs,
                         *stack_limit,
                         *rss_limit,
                         time_limit_per_input,
                         *std::move(crashing_input_to_reproduce)};
  }();
}

#undef ASSIGN_OR_RETURN

}  // namespace fuzztest::internal
