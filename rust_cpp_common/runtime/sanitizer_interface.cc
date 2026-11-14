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

#include "./rust_cpp_common/runtime/sanitizer_interface.h"

#if (defined(__linux__) || defined(__APPLE__)) && defined(__has_include)
#if __has_include(<unwind.h>)
#include <unwind.h>
#define FUZZTEST_HAS_UNWIND_H 1
#endif
#endif

#if defined(__linux__)
#include <ucontext.h>
#endif

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>

#include "absl/base/attributes.h"
#include "absl/base/config.h"  // IWYU pragma: keep
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
#include "./rust_cpp_common/runtime/symbol_name_utils.h"

#if defined(ABSL_HAVE_THREAD_SANITIZER)
#include <sanitizer/tsan_interface.h>
#endif

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

// Returns the PC of the code interrupted by a signal, given the `ucontext`
// passed to the signal handler, or null if unknown. Async-signal-safe.
void* GetInterruptedPc(const void* ucontext) {
  if (ucontext == nullptr) return nullptr;
#if defined(__linux__) && defined(__x86_64__)
  return reinterpret_cast<void*>(
      static_cast<const ucontext_t*>(ucontext)->uc_mcontext.gregs[REG_RIP]);
#elif defined(__linux__) && defined(__aarch64__)
  return reinterpret_cast<void*>(
      static_cast<const ucontext_t*>(ucontext)->uc_mcontext.pc);
#else
  return nullptr;
#endif
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
#if defined(__arm__) && !defined(__USING_SJLJ_EXCEPTIONS__) && \
    !defined(__ARM_DWARF_EH__) && !defined(__SEH__)
  // The ARM EHABI unwinder (e.g., libgcc_s on 32-bit ARM) doesn't export
  // `_Unwind_GetIPInfo`. Like libgcc's ARM `unwind.h`, use the inline
  // `_Unwind_GetIP`, which never points before the instruction.
  uintptr_t ip = _Unwind_GetIP(context);
#else
  uintptr_t ip = _Unwind_GetIPInfo(context, &ip_before_insn);
#endif
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

#if defined(ABSL_HAVE_THREAD_SANITIZER)
constexpr size_t kSleepTraceSize = 16;

absl::string_view ExtractAppFunctionFromTsanMop(void* report, size_t mop_idx,
                                                absl::Span<char> symbol_buf) {
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
  for (void* pc : trace) {
    if (pc == nullptr) {
      break;
    }
    if (std::optional<absl::string_view> func_name =
            SymbolizeAppFunction(pc, symbol_buf.data(), symbol_buf.size());
        func_name.has_value()) {
      return *func_name;
    }
  }
  return "";
}

// If `report` is a ThreadSanitizer race report (`data-race`, `data-race-vptr`,
// or `external-race`) with two memory operations, sets `f0` and `f1` to the top
// application functions of the two racing memory operations (symbolized into
// `symbol_storage`, or empty if there are none) and returns true. Otherwise,
// returns false.
bool GetTsanRaceAppFunctions(void* report, absl::Span<char> symbol_storage,
                             absl::string_view& f0, absl::string_view& f1) {
  const char* description = nullptr;
  int count = 0;
  int stack_count = 0;
  int mop_count = 0;
  int loc_count = 0;
  int mutex_count = 0;
  int thread_count = 0;
  int unique_tid_count = 0;
  void* sleep_trace[kSleepTraceSize] = {nullptr};
  if (!__tsan_get_report_data(report, &description, &count, &stack_count,
                              &mop_count, &loc_count, &mutex_count,
                              &thread_count, &unique_tid_count, sleep_trace,
                              kSleepTraceSize)) {
    return false;
  }
  // Other reports with two memory operations (e.g., `heap-use-after-free`) are
  // always detected by the same (accessing) thread, so their single-thread
  // stack signature is already deterministic.
  const absl::string_view desc = description == nullptr ? "" : description;
  const bool is_race = desc == "data-race" || desc == "data-race-vptr" ||
                       desc == "external-race";
  if (!is_race || mop_count < 2) return false;
  const size_t half = symbol_storage.size() / 2;
  f0 = ExtractAppFunctionFromTsanMop(report, 0, symbol_storage.first(half));
  f1 = ExtractAppFunctionFromTsanMop(report, 1, symbol_storage.subspan(half));
  return true;
}
#endif  // defined(ABSL_HAVE_THREAD_SANITIZER)

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
    absl::Span<absl::string_view> out_frames, absl::Span<char> symbol_storage,
    const void* ucontext) {
  if (out_frames.empty() || symbol_storage.empty()) {
    return {};
  }

  // Leave room in front of the unwound frames for the interrupted PC.
  void* stack[kMaxStackFrames + 1] = {};
  void** const unwound = stack + 1;
  int depth = 0;
#if defined(FUZZTEST_HAS_UNWIND_H)
  // In a signal handler (`ucontext != nullptr`), don't use `_Unwind_Backtrace`:
  // it isn't async-signal-safe (e.g., it may take the dynamic linker's lock or
  // allocate), so it may deadlock if the crash happened while holding such a
  // lock (e.g., in `malloc`). Use Abseil's signal-safe unwinder instead.
  if (ucontext == nullptr) {
    UnwindState state = {unwound, /*count=*/0, kMaxStackFrames,
                         /*skip_count=*/1};
    _Unwind_Backtrace(&UnwindCallback, &state);
    depth = state.count;
  }
#endif
  if (depth == 0) {
    // With `ucontext`, Abseil's unwinder can unwind through the signal frame
    // (e.g., from an alternate signal stack).
    depth = absl::GetStackTraceWithContext(unwound, kMaxStackFrames,
                                           /*skip_count=*/1, ucontext,
                                           /*min_dropped_frames=*/nullptr);
    for (int i = 0; i < depth; ++i) {
      const uintptr_t ip = reinterpret_cast<uintptr_t>(unwound[i]);
      if (ip > 0) {
        unwound[i] = reinterpret_cast<void*>(ip - 1);
      }
    }
  }

  void** frames = unwound;
  int num_pcs = depth;
  if (void* const interrupted_pc = GetInterruptedPc(ucontext);
      interrupted_pc != nullptr) {
    // Unwinding from within a signal handler may skip the frame of the
    // interrupted function (e.g., frame-pointer unwinding goes from the handler
    // directly to the interrupted function's caller). If the unwound stack
    // contains the interrupted PC, start from there. Otherwise, prepend it.
    const uintptr_t pc = reinterpret_cast<uintptr_t>(interrupted_pc);
    int i = 0;
    while (i < depth && reinterpret_cast<uintptr_t>(unwound[i]) != pc &&
           reinterpret_cast<uintptr_t>(unwound[i]) != pc - 1) {
      ++i;
    }
    if (i < depth) {
      frames = unwound + i;
      num_pcs = depth - i;
    } else {
      stack[0] = interrupted_pc;
      frames = stack;
      num_pcs = depth + 1;
    }
  }

  size_t num_frames = 0;
  size_t storage_offset = 0;
  for (int i = 0; i < num_pcs && num_frames < out_frames.size() &&
                  storage_offset < symbol_storage.size();
       ++i) {
    char* current_buf = symbol_storage.data() + storage_offset;
    const size_t remaining_storage = symbol_storage.size() - storage_offset;
    if (std::optional<absl::string_view> func_name =
            SymbolizeAppFunction(frames[i], current_buf, remaining_storage);
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

absl::string_view FormatTwoThreadCrashSignature(absl::string_view crash_type,
                                                absl::string_view f0,
                                                absl::string_view f1,
                                                absl::Span<char> out_buffer) {
  if (f0.empty() && f1.empty()) {
    return crash_type;
  }
  const absl::string_view resolved_f0 = f0.empty() ? "<unknown>" : f0;
  const absl::string_view resolved_f1 = f1.empty() ? "<unknown>" : f1;
  size_t offset = 0;
  AppendToBuffer(out_buffer, offset, crash_type);
  AppendToBuffer(out_buffer, offset, ":");
  AppendToBuffer(out_buffer, offset, std::min(resolved_f0, resolved_f1));
  AppendToBuffer(out_buffer, offset, " <-> ");
  AppendToBuffer(out_buffer, offset, std::max(resolved_f0, resolved_f1));
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
    const char* crash_type_data, size_t crash_type_size, const void* ucontext,
    char* out, size_t out_size) {
  const absl::string_view crash_type(crash_type_data, crash_type_size);
  const absl::Span<char> out_buffer(out, out_size);
  if (fuzztest::internal::crash_signature_scratch_busy.test_and_set(
          std::memory_order_acquire)) {
    return fuzztest::internal::CopyToBuffer(crash_type, out_buffer);
  }
  const absl::Span<const absl::string_view> frames =
      fuzztest::internal::GetTopAppFunctions(
          fuzztest::internal::crash_signature_frame_storage,
          fuzztest::internal::crash_signature_symbol_storage, ucontext);
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
#if defined(ABSL_HAVE_THREAD_SANITIZER)
  // ThreadSanitizer sets the current report of the reporting thread before
  // printing it, which calls the sanitizer error summary hook. For race
  // reports (per TSan's report type, independently of the crash type parsed
  // from the summary), use the commutative two-thread signature of the two
  // racing memory operations, which doesn't depend on which thread detected
  // the race. Otherwise (e.g., no current report, as for deadly signals), fall
  // back to the stack signature.
  if (void* const report = __tsan_get_current_report(); report != nullptr) {
    const absl::string_view crash_type(crash_type_data, crash_type_size);
    const absl::Span<char> out_buffer(out, out_size);
    if (fuzztest::internal::crash_signature_scratch_busy.test_and_set(
            std::memory_order_acquire)) {
      return fuzztest::internal::CopyToBuffer(crash_type, out_buffer);
    }
    absl::string_view f0;
    absl::string_view f1;
    const bool has_race_frames =
        fuzztest::internal::GetTsanRaceAppFunctions(
            report, fuzztest::internal::crash_signature_symbol_storage, f0,
            f1) &&
        !(f0.empty() && f1.empty());
    size_t size = 0;
    if (has_race_frames) {
      size = fuzztest::internal::CopyToBuffer(
          fuzztest::internal::FormatTwoThreadCrashSignature(crash_type, f0, f1,
                                                            out_buffer),
          out_buffer);
    }
    fuzztest::internal::crash_signature_scratch_busy.clear(
        std::memory_order_release);
    if (has_race_frames) return size;
  }
#endif  // defined(ABSL_HAVE_THREAD_SANITIZER)
  return FuzzTestComputeStackCrashSignature(crash_type_data, crash_type_size,
                                            /*ucontext=*/nullptr, out,
                                            out_size);
}
