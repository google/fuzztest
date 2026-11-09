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

#if (defined(__linux__) || defined(__APPLE__)) && defined(__has_include)
#if __has_include(<unwind.h>)
#include <unwind.h>
#define FUZZTEST_HAS_UNWIND_H 1
#endif
#endif

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>

#include "absl/base/attributes.h"
#include "absl/debugging/stacktrace.h"
#include "absl/debugging/symbolize.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "absl/types/span.h"
#include "./common/logging.h"
#include "./fuzztest/internal/symbol_name_utils.h"

namespace fuzztest::internal {

std::atomic<FuzzTestSanitizerErrorSummaryCallback>
    sanitizer_error_summary_callback{nullptr};

namespace {

constexpr int kMaxStackFrames = 64;

constexpr absl::string_view kInternalPrefixes[] = {
    "Centipede",
    "FuzzTestSetSanitizerErrorSummaryCallback",
    "FuzzTestWorker",
    "__",
    "_start",
    "absl::",
    "asan_",
    "centipede::",
    "fuzztest::",
    "hwasan_",
    "lsan_",
    "msan_",
    "sanitizer_",
    "std::",
    "tcmalloc::",
    "testing::",
    "tsan_",
    "ubsan_",
};

// Exact function names. Names covered by `kInternalPrefixes` (e.g., `__clone`)
// are omitted.
constexpr absl::string_view kInternalFunctions[] = {
    "FuzzTestComputeSanitizerCrashSignature",
    "FuzzTestComputeStackCrashSignature",
    "RUN_ALL_TESTS",
    "SignalAction",
    "SignalHandler",
    "abort",
    "aligned_alloc",
    "calloc",
    "cfree",
    "clone",
    "free",
    "gsignal",
    "killpg",
    "main",
    "malloc",
    "operator delete",
    "operator delete[]",
    "operator new",
    "operator new[]",
    "posix_memalign",
    "pthread_kill",
    "pvalloc",
    "raise",
    "realloc",
    "ssignal",
    "start_thread",
    "syscall",
    "valloc",
};

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

absl::string_view NormalizeSymbol(absl::string_view symbol) {
  symbol = absl::StripAsciiWhitespace(symbol);
  ConsumeFileAndLineNumber(symbol);
  absl::ConsumeSuffix(&symbol, "()");
  while (absl::EndsWith(symbol, "]")) {
    const size_t abi_pos = symbol.rfind("[abi:");
    if (abi_pos == absl::string_view::npos) break;
    symbol.remove_suffix(symbol.size() - abi_pos);
  }
  return absl::StripAsciiWhitespace(symbol);
}

bool IsInternalFrame(absl::string_view func) {
  if (func.empty() || func == "<unknown>" || func == "(unknown)") {
    return true;
  }
  if (absl::StrContains(func, "fuzztest::internal") ||
      absl::StrContains(func, "testing::internal")) {
    return true;
  }

  for (const absl::string_view prefix : kInternalPrefixes) {
    if (absl::StartsWith(func, prefix)) {
      return true;
    }
  }

  for (const absl::string_view internal_func : kInternalFunctions) {
    if (func == internal_func) {
      return true;
    }
  }

  return false;
}

std::optional<absl::string_view> SymbolizeAppFunction(void* pc,
                                                      char* symbol_buf,
                                                      size_t symbol_buf_size) {
  if (symbol_buf_size == 0 ||
      !absl::Symbolize(pc, symbol_buf, symbol_buf_size)) {
    return std::nullopt;
  }
  const absl::string_view func_name = NormalizeSymbol(symbol_buf);
  if (IsInternalFrame(func_name)) {
    return std::nullopt;
  }
  return func_name;
}

void AppendToBuffer(absl::Span<char> out_buffer, size_t& offset,
                    absl::string_view piece) {
  if (offset >= out_buffer.size() || piece.empty()) return;
  const size_t to_copy = std::min(piece.size(), out_buffer.size() - offset);
  std::memcpy(out_buffer.data() + offset, piece.data(), to_copy);
  offset += to_copy;
}

// Copies `value` into `out_buffer` (unless it already starts there), truncating
// it to `out_buffer.size()`. Returns the number of bytes copied.
size_t CopyToBuffer(absl::string_view value, absl::Span<char> out_buffer) {
  const size_t size = std::min(value.size(), out_buffer.size());
  if (value.data() != out_buffer.data() && size > 0) {
    std::memmove(out_buffer.data(), value.data(), size);
  }
  return size;
}

// Process-wide scratch storage for computing crash signatures in the
// `FuzzTestCompute*CrashSignature()` functions, kept off the stack to avoid
// using a lot of stack space (e.g., on an alternate signal stack). Only used by
// the thread that sets `crash_signature_scratch_busy`.
std::atomic_flag crash_signature_scratch_busy = ATOMIC_FLAG_INIT;
absl::string_view crash_signature_frame_storage[3];
char crash_signature_symbol_storage[3 * 1024];

#if defined(FUZZTEST_HAS_UNWIND_H)
struct UnwindState {
  void** stack;
  int count;
  int max_frames;
  int skip_count;
};

ABSL_ATTRIBUTE_NO_SANITIZE_ADDRESS
ABSL_ATTRIBUTE_NO_SANITIZE_MEMORY
ABSL_ATTRIBUTE_NO_SANITIZE_THREAD
_Unwind_Reason_Code UnwindCallback(_Unwind_Context* context, void* arg) {
  auto* state = static_cast<UnwindState*>(arg);
  int ip_before_insn = 0;
  uintptr_t ip = _Unwind_GetIPInfo(context, &ip_before_insn);
  if (ip == 0) {
    return _URC_END_OF_STACK;
  }
  if (!ip_before_insn) {
    --ip;
  }
  if (state->skip_count > 0) {
    --state->skip_count;
    return _URC_NO_REASON;
  }
  if (state->count >= state->max_frames) {
    return _URC_END_OF_STACK;
  }
  state->stack[state->count++] = reinterpret_cast<void*>(ip);
  return _URC_NO_REASON;
}
#endif  // defined(FUZZTEST_HAS_UNWIND_H)

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

absl::Span<const absl::string_view> GetTopAppFunctions(
    absl::Span<absl::string_view> out_frames, absl::Span<char> symbol_storage) {
  if (out_frames.empty() || symbol_storage.empty()) {
    return {};
  }

  void* stack[kMaxStackFrames] = {};
  int depth = 0;
#if defined(FUZZTEST_HAS_UNWIND_H)
  UnwindState state = {stack, /*count=*/0, kMaxStackFrames, /*skip_count=*/1};
  _Unwind_Backtrace(&UnwindCallback, &state);
  depth = state.count;
#endif
  if (depth == 0) {
    depth = absl::GetStackTrace(stack, kMaxStackFrames, /*skip_count=*/1);
    for (int i = 0; i < depth; ++i) {
      const uintptr_t ip = reinterpret_cast<uintptr_t>(stack[i]);
      if (ip > 0) {
        stack[i] = reinterpret_cast<void*>(ip - 1);
      }
    }
  }

  size_t num_frames = 0;
  size_t storage_offset = 0;
  for (int i = 0; i < depth && num_frames < out_frames.size() &&
                  storage_offset < symbol_storage.size();
       ++i) {
    char* current_buf = symbol_storage.data() + storage_offset;
    const size_t remaining_storage = symbol_storage.size() - storage_offset;
    if (std::optional<absl::string_view> func_name =
            SymbolizeAppFunction(stack[i], current_buf, remaining_storage);
        func_name.has_value()) {
      // Compact `func_name` to the start of `current_buf` so `symbol_storage`
      // only advances by `func_name->size()`.
      if (func_name->data() != current_buf) {
        std::memmove(current_buf, func_name->data(), func_name->size());
      }
      out_frames[num_frames++] =
          absl::string_view(current_buf, func_name->size());
      storage_offset += func_name->size();
    }
  }
  return out_frames.first(num_frames);
}

absl::string_view FormatStackCrashSignature(
    absl::string_view crash_type, absl::Span<const absl::string_view> frames,
    absl::Span<char> out_buffer) {
  if (frames.empty()) {
    return crash_type;
  }
  size_t offset = 0;
  AppendToBuffer(out_buffer, offset, crash_type);
  AppendToBuffer(out_buffer, offset, ":");
  for (size_t i = 0; i < frames.size(); ++i) {
    if (i > 0) {
      AppendToBuffer(out_buffer, offset, "/");
    }
    AppendToBuffer(out_buffer, offset, frames[i]);
  }
  return absl::string_view(out_buffer.data(), offset);
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

extern "C" size_t FuzzTestFormatCrashDescription(
    const char* prefix, size_t prefix_size, const char* crash_type,
    size_t crash_type_size, const char* signature, size_t signature_size,
    char* out, size_t out_size) {
  const absl::Span<char> out_buffer(out, out_size);
  size_t offset = 0;
  fuzztest::internal::AppendToBuffer(out_buffer, offset,
                                     absl::string_view(prefix, prefix_size));
  fuzztest::internal::AppendToBuffer(
      out_buffer, offset, absl::string_view(crash_type, crash_type_size));
  if (signature_size > 0) {
    fuzztest::internal::AppendToBuffer(out_buffer, offset,
                                       "\nCRASH_SIGNATURE=");
    fuzztest::internal::AppendToBuffer(
        out_buffer, offset, absl::string_view(signature, signature_size));
  }
  return offset;
}

extern "C" size_t FuzzTestComputeStackCrashSignature(
    const char* crash_type_data, size_t crash_type_size, char* out,
    size_t out_size) {
  const absl::string_view crash_type(crash_type_data, crash_type_size);
  const absl::Span<char> out_buffer(out, out_size);
  if (fuzztest::internal::crash_signature_scratch_busy.test_and_set(
          std::memory_order_acquire)) {
    return fuzztest::internal::CopyToBuffer(crash_type, out_buffer);
  }
  const absl::Span<const absl::string_view> frames =
      fuzztest::internal::GetTopAppFunctions(
          fuzztest::internal::crash_signature_frame_storage,
          fuzztest::internal::crash_signature_symbol_storage);
  const size_t size = fuzztest::internal::CopyToBuffer(
      fuzztest::internal::FormatStackCrashSignature(crash_type, frames,
                                                    out_buffer),
      out_buffer);
  fuzztest::internal::crash_signature_scratch_busy.clear(
      std::memory_order_release);
  return size;
}

extern "C" size_t FuzzTestComputeSanitizerCrashSignature(
    const char* crash_type_data, size_t crash_type_size, char* out,
    size_t out_size) {
  return FuzzTestComputeStackCrashSignature(crash_type_data, crash_type_size,
                                            out, out_size);
}
