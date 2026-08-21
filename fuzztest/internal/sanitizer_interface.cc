// Copyright 2025 Google LLC
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

#include "./fuzztest/internal/sanitizer_interface.h"

#include <cstddef>
#include <optional>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"

namespace fuzztest::internal {
namespace {

std::optional<std::string> MaybeExtractTsanCrashType(
    absl::string_view sanitizer_name, absl::string_view error_summary) {
  if (sanitizer_name != "ThreadSanitizer") return std::nullopt;

  if (absl::StartsWith(error_summary, "data race") ||
      absl::StartsWith(error_summary, "race on") ||
      absl::StartsWith(error_summary, "Swift access race")) {
    return "data-race";
  }
  if (absl::StartsWith(error_summary, "destroy of a locked mutex")) {
    return "destroy-locked-mutex";
  }
  if (absl::StartsWith(error_summary, "double lock of a mutex")) {
    return "double-lock-of-mutex";
  }
  if (absl::StartsWith(error_summary, "lock-order-inversion")) {
    return "lock-order-inversion";
  }
  if (absl::StartsWith(error_summary, "mutex held in the wrong context")) {
    return "mutex-held-in-wrong-context";
  }
  if (absl::StartsWith(error_summary, "read lock of a write locked mutex")) {
    return "read-lock-of-write-locked-mutex";
  }
  if (absl::StartsWith(error_summary, "read unlock of a write locked mutex")) {
    return "read-unlock-of-write-locked-mutex";
  }
  if (absl::StartsWith(error_summary, "signal handler spoils errno")) {
    return "signal-handler-spoils-errno";
  }
  if (absl::StartsWith(error_summary, "signal-unsafe call")) {
    return "signal-unsafe-call-inside-of-a-signal";
  }
  if (absl::StartsWith(error_summary, "thread leak")) {
    return "thread-leak";
  }
  if (absl::StartsWith(error_summary, "unlock of an unlocked mutex")) {
    return "unlock-unlocked-mutex";
  }
  if (absl::StartsWith(error_summary, "use of an invalid mutex")) {
    return "use-invalid-mutex";
  }
  return std::nullopt;
}

}  // namespace

absl::StatusOr<std::string> ParseCrashTypeFromSanitizerSummary(
    absl::string_view error_summary) {
  if (!absl::ConsumePrefix(&error_summary, "SUMMARY: ")) {
    return absl::InvalidArgumentError(absl::StrCat(
        "No `SUMMARY: ` prefix in sanitizer error summary: ", error_summary));
  }
  const size_t colon_pos = error_summary.find(": ");
  if (colon_pos == error_summary.npos) {
    return absl::InvalidArgumentError(absl::StrCat(
        "No `: ` following the sanitizer name in sanitizer error summary: ",
        error_summary));
  }
  const absl::string_view sanitizer_name = error_summary.substr(0, colon_pos);
  error_summary.remove_prefix(colon_pos + 2);
  // Explicitly handle summaries like:
  // SUMMARY: AddressSanitizer: 1000 byte(s) leaked in 1000 allocation(s).
  if (error_summary.find("byte(s) leaked") != error_summary.npos) {
    return "memory-leak";
  }
  if (auto tsan_crash_type =
          MaybeExtractTsanCrashType(sanitizer_name, error_summary);
      tsan_crash_type.has_value()) {
    return *tsan_crash_type;
  }
  const size_t space_pos = error_summary.find(' ');
  return std::string(error_summary.substr(0, space_pos));
}

}  // namespace fuzztest::internal
