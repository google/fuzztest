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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_SANITIZER_INTERFACE_H_
#define FUZZTEST_FUZZTEST_INTERNAL_SANITIZER_INTERFACE_H_

#include <cstddef>

#include "absl/base/attributes.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"

extern "C" {

using FuzzTestSanitizerErrorSummaryCallback =
    void (*)(const char* crash_type_data, size_t crash_type_size);

// Registers a callback to be invoked with the parsed crash type whenever the
// sanitizer runtime reports an error summary.
//
// The `(crash_type_data, crash_type_size)` slice passed to `callback` is
// non-null and non-empty (`crash_type_size > 0`), points either to a static
// string literal or into the `error_summary` buffer passed by the sanitizer
// runtime, and is valid for reads for the duration of the callback invocation
// (or longer if the input `error_summary` outlives the call).
void FuzzTestSetSanitizerErrorSummaryCallback(
    FuzzTestSanitizerErrorSummaryCallback callback);

}  // extern "C"

namespace fuzztest::internal {

// Parses the crash type from the sanitizer error summary.
// The summary is expected to be in the format:
// "SUMMARY: SomeSanitizer: some-crash-type ..."
//
// The returned `absl::string_view` points either to a static string literal or
// into `error_summary`, and remains valid for as long as `error_summary` is
// valid.
absl::StatusOr<absl::string_view> ParseCrashTypeFromSanitizerSummary(
    absl::string_view error_summary ABSL_ATTRIBUTE_LIFETIME_BOUND);

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_SANITIZER_INTERFACE_H_
