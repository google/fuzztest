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

#if defined(THREAD_SANITIZER)
#include <sanitizer/tsan_interface.h>
#endif

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/debugging/stacktrace.h"
#include "absl/debugging/symbolize.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/ascii.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "absl/types/span.h"
#include "./common/logging.h"
#include "./fuzztest/internal/type_support.h"

namespace fuzztest::internal {

std::atomic<FuzzTestSanitizerErrorSummaryCallback>
    sanitizer_error_summary_callback{nullptr};
std::atomic<FuzzTestTsanOnReportCallback> tsan_on_report_callback{nullptr};

namespace {

constexpr int kMaxStackFrames = 64;

constexpr absl::string_view kInternalPrefixes[] = {
    "__",
    "sanitizer_",
    "asan_",
    "msan_",
    "tsan_",
    "ubsan_",
    "lsan_",
    "hwasan_",
    "fuzztest::",
    "centipede::",
    "FuzzTestWorker",
    "Centipede",
    "LLVMFuzzer",
    "testing::",
    "absl::",
    "std::",
    "tcmalloc::",
    "FuzzTestSetSanitizerErrorSummaryCallback",
    "FuzzTestSetTsanOnReportCallback",
    "_start",
};

constexpr absl::string_view kInternalFunctions[] = {
    "abort",
    "raise",
    "gsignal",
    "ssignal",
    "killpg",
    "SignalAction",
    "SignalHandler",
    "pthread_kill",
    "__pthread_kill",
    "start_thread",
    "clone",
    "__clone",
    "_start",
    "__libc_start_main",
    "main",
    "RUN_ALL_TESTS",
    "syscall",
    "malloc",
    "calloc",
    "realloc",
    "free",
    "cfree",
    "aligned_alloc",
    "posix_memalign",
    "valloc",
    "pvalloc",
    "operator new",
    "operator new[]",
    "operator delete",
    "operator delete[]",
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

std::optional<std::string> SymbolizeAppFunction(void* pc, char* symbol_buf,
                                                size_t symbol_buf_size) {
  if (!absl::Symbolize(pc, symbol_buf, symbol_buf_size)) {
    return std::nullopt;
  }
  const absl::string_view func_name = NormalizeSymbol(symbol_buf);
  if (IsInternalFrame(func_name)) {
    return std::nullopt;
  }
  return std::string(func_name);
}

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

#if defined(THREAD_SANITIZER)
constexpr size_t kSleepTraceSize = 16;

std::string ExtractAppFunctionFromTsanMop(void* report, size_t mop_idx) {
  int tid = 0;
  void* addr = nullptr;
  int size = 0;
  int write = 0;
  int atomic = 0;
  void* trace[kMaxStackFrames] = {nullptr};
  if (!__tsan_get_report_mop(report, mop_idx, &tid, &addr, &size, &write,
                             &atomic, trace, kMaxStackFrames)) {
    return "";
  }
  char symbol_buf[1024];
  for (void* pc : trace) {
    if (pc == nullptr) {
      break;
    }
    if (std::optional<std::string> func_name =
            SymbolizeAppFunction(pc, symbol_buf, sizeof(symbol_buf));
        func_name.has_value()) {
      return *std::move(func_name);
    }
  }
  return "";
}
#endif  // defined(THREAD_SANITIZER)

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

std::vector<std::string> GetTopAppFunctions(int max_frames) {
  std::vector<std::string> app_functions;
  if (max_frames <= 0) {
    return app_functions;
  }
  app_functions.reserve(max_frames);

  void* stack[kMaxStackFrames] = {nullptr};
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

  char symbol_buf[1024];
  for (int i = 0;
       i < depth && static_cast<int>(app_functions.size()) < max_frames; ++i) {
    if (std::optional<std::string> func_name =
            SymbolizeAppFunction(stack[i], symbol_buf, sizeof(symbol_buf));
        func_name.has_value()) {
      app_functions.push_back(*std::move(func_name));
    }
  }
  return app_functions;
}

std::string FormatStackCrashSignature(absl::string_view crash_type,
                                      absl::Span<const std::string> frames) {
  if (frames.empty()) {
    return std::string(crash_type);
  }
  return absl::StrCat(crash_type, ":", absl::StrJoin(frames, "/"));
}

std::string FormatTwoThreadCrashSignature(absl::string_view crash_type,
                                          absl::string_view f0,
                                          absl::string_view f1) {
  if (f0.empty() && f1.empty()) {
    return std::string(crash_type);
  }
  const absl::string_view resolved_f0 = f0.empty() ? "<unknown>" : f0;
  const absl::string_view resolved_f1 = f1.empty() ? "<unknown>" : f1;
  return absl::StrCat(crash_type, ":", std::min(resolved_f0, resolved_f1),
                      " <-> ", std::max(resolved_f0, resolved_f1));
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

#if defined(THREAD_SANITIZER)
extern "C" void __attribute__((visibility("default"),
                               used)) __tsan_on_report(void* report) {
  const FuzzTestTsanOnReportCallback callback =
      fuzztest::internal::tsan_on_report_callback.load(
          std::memory_order_relaxed);
  if (callback == nullptr || report == nullptr) return;

  const char* description = nullptr;
  int count = 0;
  int stack_count = 0;
  int mop_count = 0;
  int loc_count = 0;
  int mutex_count = 0;
  int thread_count = 0;
  int unique_tid_count = 0;
  void* sleep_trace[fuzztest::internal::kSleepTraceSize] = {nullptr};
  if (!__tsan_get_report_data(report, &description, &count, &stack_count,
                              &mop_count, &loc_count, &mutex_count,
                              &thread_count, &unique_tid_count, sleep_trace,
                              fuzztest::internal::kSleepTraceSize)) {
    return;
  }
  if (mop_count < 2) return;

  const std::string f0 =
      fuzztest::internal::ExtractAppFunctionFromTsanMop(report, 0);
  const std::string f1 =
      fuzztest::internal::ExtractAppFunctionFromTsanMop(report, 1);
  callback(f0.data(), f0.size(), f1.data(), f1.size());
}
#endif  // defined(THREAD_SANITIZER)

extern "C" void FuzzTestSetTsanOnReportCallback(
    FuzzTestTsanOnReportCallback callback) {
#if defined(THREAD_SANITIZER)
  // Ensure the TSan report hook is retained by the linker (e.g., under
  // -Wl,--gc-sections) whenever a callback is registered.
  void (*volatile hook)(void*) = &__tsan_on_report;
  (void)hook;
#endif
  fuzztest::internal::tsan_on_report_callback.store(callback,
                                                    std::memory_order_relaxed);
}
