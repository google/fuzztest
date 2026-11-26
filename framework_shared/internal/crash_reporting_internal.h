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

#ifndef FUZZTEST_FRAMEWORK_SHARED_INTERNAL_CRASH_REPORTING_INTERNAL_H_
#define FUZZTEST_FRAMEWORK_SHARED_INTERNAL_CRASH_REPORTING_INTERNAL_H_

#include "absl/base/attributes.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"

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

// Captures the current stack trace, symbolizes each PC into `symbol_storage`,
// filters out internal frames, strips trailing parameter lists `(...)` and
// file/line info, and populates up to `out_frames.size()` application function
// names in `out_frames`.
//
// If called from a signal handler, `ucontext` should be the `ucontext_t*`
// passed to the handler (or null otherwise). It is used to include the frame
// of the interrupted function, which stack unwinding from within the handler
// may otherwise miss.
//
// Returns the subspan of `out_frames` that was populated, with each
// `absl::string_view` pointing into `symbol_storage`.
absl::Span<const absl::string_view> GetTopAppFunctions(
    absl::Span<absl::string_view> out_frames ABSL_ATTRIBUTE_LIFETIME_BOUND,
    absl::Span<char> symbol_storage ABSL_ATTRIBUTE_LIFETIME_BOUND,
    const void* ucontext = nullptr);

// Formats a stack-based crash signature from `crash_type` and `frames` into
// `out_buffer`:
// - Returns `crash_type` if `frames` is empty.
// - Otherwise writes `<crash_type>:<f0>/<f1>/...` into `out_buffer` and returns
//   a view into `out_buffer`.
absl::string_view FormatStackCrashSignature(
    absl::string_view crash_type, absl::Span<const absl::string_view> frames,
    absl::Span<char> out_buffer ABSL_ATTRIBUTE_LIFETIME_BOUND);

// Formats a commutative two-thread crash signature from `crash_type`, `f0`, and
// `f1` into `out_buffer`:
// - Returns `crash_type` if both `f0` and `f1` are empty.
// - Otherwise substitutes `"<unknown>"` for an empty frame, writes
//   `<crash_type>:<min(f0, f1)> <-> <max(f0, f1)>` into `out_buffer`, and
//   returns a view into `out_buffer`.
absl::string_view FormatTwoThreadCrashSignature(
    absl::string_view crash_type, absl::string_view f0, absl::string_view f1,
    absl::Span<char> out_buffer ABSL_ATTRIBUTE_LIFETIME_BOUND);

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FRAMEWORK_SHARED_INTERNAL_CRASH_REPORTING_INTERNAL_H_
