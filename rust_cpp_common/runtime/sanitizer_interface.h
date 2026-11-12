// Copyright 2025 Google LLC
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

#ifndef FUZZTEST_RUST_CPP_COMMON_RUNTIME_SANITIZER_INTERFACE_H_
#define FUZZTEST_RUST_CPP_COMMON_RUNTIME_SANITIZER_INTERFACE_H_

#include <cstddef>

#include "absl/base/attributes.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"

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

// Formats a crash description into `(out, out_size)`: writes
// `<prefix><crash_type>` and, only if `signature_size > 0`, the metadata line
// `\nCRASH_SIGNATURE=<signature>`. The output is truncated to `out_size` bytes
// and is not null-terminated. Returns the number of bytes written.
//
// Pure and async-signal-safe (does not allocate).
size_t FuzzTestFormatCrashDescription(const char* prefix, size_t prefix_size,
                                      const char* crash_type,
                                      size_t crash_type_size,
                                      const char* signature,
                                      size_t signature_size, char* out,
                                      size_t out_size);

// Computes a stack-based crash signature `<crash_type>:<f0>/<f1>/<f2>` from
// `crash_type` and the top (up to three) application functions on the current
// stack, and writes it into `(out, out_size)`. Writes just `crash_type` if
// there are no application frames, or if another thread is concurrently
// computing a crash signature (see below). The output is truncated to
// `out_size` bytes and is not null-terminated. Returns the number of bytes
// written.
//
// If called from a signal handler, `ucontext` should be the `ucontext_t*`
// passed to the handler (or null otherwise), so that the signature includes the
// interrupted function (see `GetTopAppFunctions()`).
//
// Async-signal-safe. To avoid using a lot of stack space (e.g., when running on
// an alternate signal stack), the frames are symbolized into process-wide
// static storage, which is guarded by a lock-free flag. Never blocks.
size_t FuzzTestComputeStackCrashSignature(const char* crash_type_data,
                                          size_t crash_type_size,
                                          const void* ucontext, char* out,
                                          size_t out_size);

// Like `FuzzTestComputeStackCrashSignature()` (with a null `ucontext`), but
// for sanitizer errors: must
// be called from the sanitizer error summary callback (see
// `FuzzTestSetSanitizerErrorSummaryCallback()`), with the crash type passed to
// the callback.
//
// For a ThreadSanitizer race report (`data-race`, `data-race-vptr`, or
// `external-race`, per the report type of `__tsan_get_current_report()`),
// writes the commutative two-thread signature
// `<crash_type>:<min(f0, f1)> <-> <max(f0, f1)>` instead, where `f0` and `f1`
// are the top application functions of the two racing memory operations (see
// `FormatTwoThreadCrashSignature()`).
size_t FuzzTestComputeSanitizerCrashSignature(const char* crash_type_data,
                                              size_t crash_type_size, char* out,
                                              size_t out_size);

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

#endif  // FUZZTEST_RUST_CPP_COMMON_RUNTIME_SANITIZER_INTERFACE_H_
