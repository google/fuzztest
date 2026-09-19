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

#include <atomic>
#include <cstddef>
#include <optional>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "./common/logging.h"

namespace fuzztest::internal {

std::atomic<FuzzTestSanitizerErrorSummaryCallback>
    sanitizer_error_summary_callback{nullptr};

namespace {

std::optional<absl::string_view> MaybeExtractTsanCrashType(
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

absl::StatusOr<absl::string_view> ParseCrashTypeFromSanitizerSummary(
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
  if (std::optional<absl::string_view> tsan_crash_type =
          MaybeExtractTsanCrashType(sanitizer_name, error_summary);
      tsan_crash_type.has_value()) {
    return *tsan_crash_type;
  }
  const size_t space_pos = error_summary.find(' ');
  return error_summary.substr(0, space_pos);
}

}  // namespace fuzztest::internal

// clang-format off
extern "C" void __attribute__((visibility("default"), used))
__sanitizer_report_error_summary(const char* error_summary) {
  const FuzzTestSanitizerErrorSummaryCallback callback =
      fuzztest::internal::sanitizer_error_summary_callback.load(
          std::memory_order_relaxed);
  if (callback == nullptr) return;
  absl::StatusOr<absl::string_view> crash_type =
      fuzztest::internal::ParseCrashTypeFromSanitizerSummary(
          absl::NullSafeStringView(error_summary));
  FUZZTEST_LOG_IF(ERROR, !crash_type.ok())
      << "Failed to extract sanitizer crash type: " << crash_type.status();
  const absl::string_view resolved_crash_type =
      crash_type.value_or("Sanitizer crash");
  callback(resolved_crash_type.data(), resolved_crash_type.size());
}
// clang-format on

extern "C" void FuzzTestSetSanitizerErrorSummaryCallback(
    FuzzTestSanitizerErrorSummaryCallback callback) {
  // Ensure the sanitizer error summary hook is retained by the linker (e.g.,
  // under -Wl,--gc-sections) whenever a callback is registered.
  void (*volatile hook)(const char*) = &__sanitizer_report_error_summary;
  (void)hook;
  fuzztest::internal::sanitizer_error_summary_callback.store(
      callback, std::memory_order_relaxed);
}
