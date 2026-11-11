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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_RUNTIME_H_
#define FUZZTEST_FUZZTEST_INTERNAL_RUNTIME_H_

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <iostream>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/functional/any_invocable.h"
#include "absl/functional/function_ref.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/discrete_distribution.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./fuzztest/internal/configuration.h"
#include "./fuzztest/internal/coverage.h"
#include "./fuzztest/internal/domains/domain.h"
#include "./fuzztest/internal/fixture_driver.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/registration.h"
#include "./fuzztest/internal/seed_seq.h"

namespace fuzztest {

// The mode in which we are running the fuzz tests.
enum class RunMode {
  // Run without instrumentation and coverage-guidance for a short time.
  kUnitTest,

  // Run coverage-guided fuzzing until a failure is detected or the test is
  // manually terminated.
  kFuzz
};

namespace internal {

class FuzzTestFuzzer {
 public:
  virtual ~FuzzTestFuzzer() = default;
  // Returns true if no error were detected by the FuzzTest, false otherwise.
  virtual bool RunInUnitTestMode(const Configuration& configuration) = 0;
  // Returns true if no error were detected by the FuzzTest, false otherwise.
  virtual bool RunInFuzzingMode(int* argc, char*** argv,
                                const Configuration& configuration) = 0;
};

class FuzzTest;

using FuzzTestFuzzerFactory =
    absl::AnyInvocable<std::unique_ptr<FuzzTestFuzzer>(const FuzzTest&) const>;

class FuzzTest {
 public:
  FuzzTest(BasicTestInfo test_info, FuzzTestFuzzerFactory factory)
      : test_info_(std::move(test_info)), make_(std::move(factory)) {}

  const std::string& suite_name() const { return test_info_.suite_name; }
  const std::string& test_name() const { return test_info_.test_name; }
  std::string full_name() const {
    return absl::StrCat(test_info_.suite_name, ".", test_info_.test_name);
  }
  const std::string& file() const { return test_info_.file; }
  int line() const { return test_info_.line; }
  bool uses_fixture() const { return test_info_.uses_fixture; }
  auto make() const { return make_(*this); }

 private:
  BasicTestInfo test_info_;
  FuzzTestFuzzerFactory make_;
};

struct RuntimeStats {
  absl::Time start_time;
  size_t runs;
  size_t edges_covered;
  size_t total_edges;
  // Number of executed inputs that increase coverage.
  size_t useful_inputs;
  size_t max_stack_used;
};

void InstallSignalHandlers(FILE* report_out);

// Returns true if FuzzTest should not install its handler for `signame` (e.g.
// "SIGSEGV"), as requested by the comma-separated list of signal names in the
// FUZZTEST_DISABLE_SIGNAL_HANDLERS environment variable. This is useful for
// targets that install their own handlers for signals they expect and recover
// from.
//
// This only covers FuzzTest's runtime and Centipede controller handlers and not
// the Centipede fork server handlers.
bool IsSignalHandlerDisabled(absl::string_view signame);

void InstallUnexpectedExitHandler();

// A function that is called when crash metadata is available.
using CrashMetadataListener = absl::AnyInvocable<void(
    absl::string_view description, absl::string_view signature) const>;
using CrashMetadataListenerRef = absl::FunctionRef<void(
    absl::string_view description, absl::string_view signature) const>;

// Returns a non-zero identifier of the calling thread on Linux and macOS, or 0
// on other platforms. Async-signal-safe.
uintptr_t GetCurrentThreadIdForCrashHandling();

// A single value recorded by `fuzztest::RecordOrDiff()`: the label (the key,
// unique within an input) and the serialized value.
struct DiffRecord {
  std::string label;
  std::string payload;

  friend bool operator==(const DiffRecord& a, const DiffRecord& b) {
    return a.label == b.label && a.payload == b.payload;
  }
};

// Encodes `records` as a record container, which is the content of a baseline
// file and the payload exchanged with the controller: `SerializeIRObject`
// (binary) of `[uint64 1, [[label, payload], ...]]`, sorted by label so that
// the encoding is deterministic. REQUIRES: labels are unique.
std::string EncodeDiffRecordContainer(std::vector<DiffRecord> records);

// Decodes a record container produced by `EncodeDiffRecordContainer`. Returns
// the records sorted by label, or nullopt if `container` is malformed, has an
// unsupported version, or has duplicate labels.
std::optional<std::vector<DiffRecord>> DecodeDiffRecordContainer(
    absl::string_view container);

// The per-input result of the incremental differential fuzzing.
struct RuntimeDiffResult {
  enum class Kind {
    // Record mode: `container` holds the records of the input.
    kRecords,
    // Validate mode: the input was executed and compared (if it had a
    // baseline). `container` is empty.
    kAck,
    // The input could not be parsed by the current domains; nothing was
    // recorded or compared. `container` is empty.
    kSkippedUnparsable,
  };
  Kind kind;
  std::string container;
};

// This class encapsulates the runtime state that is global by necessity.
// The state is accessed by calling `Runtime::instance()`, which handles the
// necessary initialization steps.
class Runtime {
 public:
  static Runtime& instance() {
    static auto* runtime = new Runtime();
    return *runtime;
  }

  void SetExternalFailureDetected(bool v) {
    external_failure_was_detected_.store(v, std::memory_order_relaxed);
  }
  bool external_failure_detected() const {
    return external_failure_was_detected_.load(std::memory_order_relaxed);
  }

  void SetSkippingRequested(bool requested) {
    skipping_requested_.store(requested, std::memory_order_relaxed);
  }

  bool skipping_requested() const {
    return skipping_requested_.load(std::memory_order_relaxed);
  }

  void SetShouldTerminateOnNonFatalFailure(bool v) {
    should_terminate_on_non_fatal_failure_ = v;
  }

  bool should_terminate_on_non_fatal_failure() const {
    return should_terminate_on_non_fatal_failure_;
  }

  void SetTerminationRequested() {
    termination_requested_.store(true, std::memory_order_relaxed);
  }

  bool termination_requested() const {
    return termination_requested_.load(std::memory_order_relaxed);
  }

  void SetRunMode(RunMode run_mode) { run_mode_ = run_mode; }
  RunMode run_mode() const { return run_mode_; }

  // Records that `InitFuzzTest` has been called.
  void SetInitFuzzTestCalled() { init_fuzztest_called_ = true; }
  bool init_fuzztest_called() const { return init_fuzztest_called_; }

  // Sets the command-line arguments passed to `InitFuzzTest`. `argc()` and
  // `argv()` are only valid after `InitFuzzTest` has been called.
  void SetArgs(int* argc, char*** argv) {
    argc_ = argc;
    argv_ = argv;
  }
  int* argc() const { return argc_; }
  char*** argv() const { return argv_; }

  // Sets the initial configuration created by `InitFuzzTest`.
  // `init_configuration()` is only valid after `InitFuzzTest` has been called.
  void SetInitConfiguration(Configuration configuration) {
    init_configuration_ = std::move(configuration);
  }
  const Configuration& init_configuration() const {
    return init_configuration_;
  }

  // Enables the crash reporter.
  // REQUIRES: `SetCurrentTest()` has been called with non-null arguments.
  void EnableReporter(const RuntimeStats* stats, absl::Time (*clock_fn)()) {
    reporter_enabled_ = true;
    re_enable_reporter_on_next_diff_input_.store(false,
                                                 std::memory_order_relaxed);
    stats_ = stats;
    clock_fn_ = clock_fn;
    // In case we have not installed them yet, do so now.
    InstallSignalHandlers(GetStderr());
    InstallUnexpectedExitHandler();
    ResetCrashType();
  }
  void DisableReporter() {
    reporter_enabled_ = false;
    re_enable_reporter_on_next_diff_input_.store(false,
                                                 std::memory_order_relaxed);
  }
  bool reporter_enabled() const { return reporter_enabled_; }

  struct Args {
    const GenericDomainCorpusType& corpus_value;
    UntypedDomain& domain;
  };

  // Sets the current test and configuration.
  // REQUIRES: Before passing null arguments, the reporter must be disabled by
  // calling `DisableReporter()`.
  void SetCurrentTest(const FuzzTest* test, const Configuration* configuration);

  void OnTestIterationStart(const absl::Time& start_time);
  void OnTestIterationEnd();

  void SetCurrentArgs(Args* args) { current_args_ = args; }
  void UnsetCurrentArgs() { current_args_ = nullptr; }

  void PrintFinalStats(absl::FormatRawSink out) const;
  void PrintFinalStatsOnDefaultSink() const;
  void PrintReport(absl::FormatRawSink out);
  void PrintReportOnDefaultSink();

  // Registers a crash metadata listener that will be called when crash metadata
  // is available.
  void RegisterCrashMetadataListener(CrashMetadataListener listener) {
    crash_metadata_listeners_.push_back(std::move(listener));
  }
  // Legacy overload for listeners that only expect the single-line crash type.
  // Such listeners receive the first line of the description (i.e.,
  // `[SETUP FAILURE: ]<crash type>`), without the metadata lines, so that any
  // signatures they derive from it remain stable.
  void RegisterCrashMetadataListener(
      absl::AnyInvocable<void(absl::string_view, absl::Span<const std::string>)
                             const>
          listener) {
    crash_metadata_listeners_.push_back(
        [listener = std::move(listener)](absl::string_view description,
                                         absl::string_view /*signature*/) {
          listener(description.substr(0, description.find('\n')), {});
        });
  }
  // Sets the crash type if it is unset. Returns true iff this call set it.
  //
  // Callers that also compute a crash signature should only do so if this
  // returns true, so that the crash type and signature describe the same
  // crash even if multiple threads fail concurrently.
  bool SetCrashTypeIfUnset(absl::string_view crash_type) {
    return crash_type_.SetIfUnset(crash_type);
  }
  std::optional<absl::string_view> crash_type() const {
    return crash_type_.Get();
  }
  bool SetCrashSignatureIfUnset(absl::string_view crash_signature) {
    return crash_signature_.SetIfUnset(crash_signature);
  }
  std::optional<absl::string_view> crash_signature() const {
    return crash_signature_.Get();
  }
  // If the crash signature is unset, sets it to a signature computed from
  // `crash_type` and the top application functions on the current stack
  // (`<crash_type>:<f0>/<f1>/<f2>`), using
  // `FuzzTestComputeStackCrashSignature()`. Async-signal-safe.
  //
  // If called from a signal handler, `ucontext` should be the `ucontext_t*`
  // passed to the handler, so that the signature includes the interrupted
  // function.
  void SetStackCrashSignatureIfUnset(absl::string_view crash_type,
                                     const void* ucontext = nullptr);
  // If another thread is writing the crash signature (e.g., computing the stack
  // crash signature in `SetStackCrashSignatureIfUnset`), waits (up to a few
  // seconds) for it to finish, so that the crash report includes the complete
  // signature. Does not wait if the calling thread is the one writing the
  // signature (e.g., if it crashed while doing so). Async-signal-safe.
  void WaitWhileCrashSignatureIsWrittenByAnotherThread() const;
  void ResetCrashType() {
    // If a thread (e.g., one that failed non-fatally during a previous input)
    // is still computing the crash signature, keep the crash type as well, so
    // that the type and signature stay consistent.
    if (crash_signature_.is_being_written()) return;
    crash_type_.Reset();
    crash_signature_.Reset();
  }

  // If the crash reporter is enabled, sets the crash type to unexpected-exit
  // and aborts the process. Otherwise, does nothing.
  void HandleUnexpectedExit();

  // Incremental differential fuzzing (`fuzztest::RecordOrDiff`).
  //
  // All state is in memory; the runtime never reads or writes baseline files.
  // The diff mode is enabled only by the Centipede runner callbacks during
  // corpus replay. When it is not enabled, `RecordOrDiff` is a no-op.

  // Enables the diff mode `mode` (which must not be `kNone`).
  void EnableDiffMode(DiffMode mode);
  // Disables the diff mode and clears the per-input diff state.
  void DisableDiffMode();
  bool diff_active() const {
    return diff_active_.load(std::memory_order_relaxed);
  }
  DiffMode diff_mode() const;

  // Starts the diff state of a new input. Must be called before running every
  // input while the diff mode is active. Resets the per-process failure state
  // (crash type and external failure flag) so that each input is reported on
  // its own. `expected_container` is the baseline record container sent by
  // the controller (validate mode), or nullopt if there is no baseline.
  // `unparsable` is true if the input could not be parsed by the current
  // domains, in which case `RecordOrDiff` is a no-op for the input.
  void BeginDiffInput(std::optional<std::string> expected_container,
                      bool unparsable);

  // The action `RecordOrDiff` should take for a single call site.
  struct DiffCallDisposition {
    enum class Kind {
      // Nothing to do: input has not begun, is unparsable, or already reported
      // a finding.
      kSkip,
      // `label` was already claimed during this input execution.
      kDuplicateLabel,
      // Record mode: serialize and pass to `AppendDiffRecord`.
      kRecord,
      // Validate mode without a decodable baseline for this input: no-op.
      kValidateNoBaseline,
      // Validate mode with a decodable baseline: compare against
      // `expected_payload` (nullopt if `label` is not in the baseline).
      kValidateWithBaseline,
    };
    Kind kind = Kind::kSkip;
    std::optional<std::string> expected_payload;
  };

  // Call-site helpers used by `fuzztest::RecordOrDiff`.
  // True iff the current input has not begun, is unparsable, or already
  // reported a RecordOrDiff finding.
  bool ShouldSkipDiffCall() const;
  // Atomically checks per-input preconditions, claims `label`, and returns the
  // disposition (and expected baseline payload, if applicable) for a single
  // `RecordOrDiff` call.
  DiffCallDisposition BeginDiffCall(const std::string& label);
  // Record mode: stores the payload of `label` for the current input.
  void AppendDiffRecord(std::string label, std::string payload);
  // Validate mode: collects a mismatch of `label`, reported at the end of the
  // input together with all other mismatches of the input.
  void AddDiffMismatch(std::string label, std::string reason,
                       std::string expected_text, std::string actual_text);
  // Reports a RecordOrDiff usage error: prints `message` to stderr and reports
  // the finding `crash_type`.
  void ReportDiffUsageError(absl::string_view message, std::string crash_type);
  // Reports a RecordOrDiff finding of `crash_type` through the crash report.
  // `is_mismatch` selects the first line of the reproduction hint.
  void ReportDiffFailure(std::string crash_type, bool is_mismatch);

  // Validate mode, at the end of an input: collects the baseline labels that
  // were not produced (and an undecodable container), and reports all
  // collected mismatches of the input as one finding `RecordOrDiff mismatch`.
  void CheckDiffRecordsAtInputEnd();

  // Returns the diff result of the current input and clears the per-input
  // state. Returns nullopt if the diff mode is not active or `BeginDiffInput`
  // was not called for the current input (e.g. the input was not executed).
  std::optional<RuntimeDiffResult> TakeDiffResult();

  class Watchdog;
  // Returns a watchdog that periodically checks the time and memory limits in a
  // separate thread. The watchdog handles the logic of starting and joining the
  // thread. The runtime must outlive the watchdog.
  Watchdog CreateWatchdog();

 private:
  Runtime();

  // Checks time and memory limits. Aborts the process if any limit is exceeded.
  void CheckWatchdogLimits();

  // Returns the file path of the reproducer.
  // Returns empty string if no reproducer file is dumped.
  std::string DumpReproducer() const;

  void ResetDiffInputState() ABSL_EXCLUSIVE_LOCKS_REQUIRED(diff_spinlock_);

  // Some failures are not necessarily detected by signal handlers or by
  // sanitizers. For example, we could have test framework failures like
  // `EXPECT_EQ` failures from GoogleTest.
  // If such a failure is detected, the external system can set
  // `external_failure_was_detected` to true to bubble it up.
  // Note: Even though failures should happen within the code under test, they
  // could be set from other threads at any moment. We make it an atomic to
  // avoid a race condition.
  std::atomic<bool> external_failure_was_detected_ = false;

  // To support in-process minimization for non-fatal failures we signal
  // suppress termination until we believe minimization is complete.
  bool should_terminate_on_non_fatal_failure_ = true;

  // If set to true in fixture setup, skips calling property functions
  // utill the matching teardown is called; If set to true in a property
  // function, skip adding the current input to the corpus when fuzzing.
  std::atomic<bool> skipping_requested_ = false;

  // If true, fuzzing should terminate as soon as possible.
  // Atomic because it is set from signal handlers.
  std::atomic<bool> termination_requested_ = false;

  RunMode run_mode_ = RunMode::kUnitTest;

  absl::Time creation_time_ = absl::Now();
  size_t test_counter_ = 0;

  std::atomic<bool> reporter_enabled_ = false;
  Args* current_args_ = nullptr;
  const FuzzTest* current_test_ = nullptr;
  const Configuration* current_configuration_;
  const RuntimeStats* stats_ = nullptr;
  absl::Time (*clock_fn_)() = nullptr;

  bool init_fuzztest_called_ = false;
  int* argc_ = nullptr;
  char*** argv_ = nullptr;
  Configuration init_configuration_;

  // We use a simple custom spinlock instead of absl::Mutex to reduce
  // dependencies and avoid potential issues with code instrumentation.
  class ABSL_LOCKABLE Spinlock {
   public:
    Spinlock() = default;
    Spinlock(const Spinlock&) = delete;
    Spinlock& operator=(const Spinlock&) = delete;

    void Lock() ABSL_EXCLUSIVE_LOCK_FUNCTION();
    void Unlock() ABSL_UNLOCK_FUNCTION();

   private:
    std::atomic_flag locked_ = ATOMIC_FLAG_INIT;
  };

  Spinlock watchdog_spinlock_;
  absl::Time current_iteration_start_time_ ABSL_GUARDED_BY(watchdog_spinlock_);
  bool test_iteration_started_ ABSL_GUARDED_BY(watchdog_spinlock_) = false;
  bool watchdog_limit_exceeded_ ABSL_GUARDED_BY(watchdog_spinlock_) = false;

  // A fixed-size string buffer that avoids heap allocations for signal safety.
  //
  // Failures may be reported concurrently from multiple threads (e.g., a
  // watchdog thread racing with a failing worker thread), so the buffer is
  // guarded by a lock-free state machine: the first writer claims the buffer
  // by transitioning `kEmpty` -> `kWriting`, and publishes it with `kReady`.
  // Readers only observe the contents once they are `kReady`. This is both
  // data-race-free and async-signal-safe (no locks that could deadlock if a
  // signal interrupts a writer on the same thread).
  template <size_t kCapacity>
  class CrashMetadataBuffer {
   public:
    // Returns true iff this call claimed the buffer and set the value.
    bool SetIfUnset(absl::string_view value) {
      return SetIfUnsetWith([value](absl::Span<char> out) {
        const size_t size = std::min(value.size(), out.size());
        if (size > 0) std::memcpy(out.data(), value.data(), size);
        return size;
      });
    }

    // If unset, claims the buffer and calls `writer(absl::Span<char> out)`,
    // which must write the value into `out` and return its size (at most
    // `out.size()`). `writer` is only called by the thread that claims the
    // buffer, so it may use storage that is shared across threads. Returns
    // true iff this call claimed the buffer.
    template <typename Writer>
    bool SetIfUnsetWith(Writer writer) {
      State expected = State::kEmpty;
      if (!state_.compare_exchange_strong(expected, State::kWriting,
                                          std::memory_order_acq_rel)) {
        return false;
      }
      writer_thread_.store(GetCurrentThreadIdForCrashHandling(),
                           std::memory_order_relaxed);
      size_ = std::min<size_t>(writer(absl::Span<char>(buffer_)), kCapacity);
      writer_thread_.store(0, std::memory_order_relaxed);
      state_.store(State::kReady, std::memory_order_release);
      return true;
    }

    // Clears a set value. Leaves an in-progress write untouched, so that a
    // concurrent writer keeps exclusive use of the buffer (and of any shared
    // storage its writer uses) until it completes.
    void Reset() {
      State expected = State::kReady;
      state_.compare_exchange_strong(expected, State::kEmpty,
                                     std::memory_order_acq_rel);
    }

    bool has_value() const {
      return state_.load(std::memory_order_acquire) == State::kReady;
    }

    // Returns true iff a thread has claimed the buffer and is still writing
    // the value.
    bool is_being_written() const {
      return state_.load(std::memory_order_acquire) == State::kWriting;
    }

    // Returns true iff the calling thread has claimed the buffer and is still
    // writing the value (e.g., if it crashed while doing so).
    bool is_being_written_by_current_thread() const {
      const uintptr_t this_thread = GetCurrentThreadIdForCrashHandling();
      return this_thread != 0 && is_being_written() &&
             writer_thread_.load(std::memory_order_relaxed) == this_thread;
    }

    std::optional<absl::string_view> Get() const {
      if (!has_value()) return std::nullopt;
      return absl::string_view(buffer_, size_);
    }

   private:
    enum class State : uint8_t { kEmpty, kWriting, kReady };

    std::atomic<State> state_ = State::kEmpty;
    // The thread that claimed the buffer while `kWriting`, or 0 (if unset or
    // unknown).
    std::atomic<uintptr_t> writer_thread_ = 0;
    char buffer_[kCapacity] = {};
    size_t size_ = 0;
  };

  // A registry of crash metadata listeners.
  std::vector<CrashMetadataListener> crash_metadata_listeners_;
  // In case of a crash, contains the crash type.
  CrashMetadataBuffer<256> crash_type_;
  // In case of a crash, contains the crash signature.
  CrashMetadataBuffer<1024> crash_signature_;

  // Incremental differential fuzzing state.
  enum class DiffReportKind { kNone, kMismatch, kError };
  struct DiffMismatch {
    std::string label;
    std::string reason;
    std::string expected_text;
    std::string actual_text;
  };
  std::atomic<bool> diff_active_ = false;
  // Set when `PrintReport` consumed `reporter_enabled_` while diff mode was
  // active, so `BeginDiffInput` can re-arm it on the next input.
  std::atomic<bool> re_enable_reporter_on_next_diff_input_ = false;
  // Set while printing the report of a RecordOrDiff finding.
  std::atomic<DiffReportKind> diff_failure_report_{DiffReportKind::kNone};
  mutable Spinlock diff_spinlock_;
  DiffMode diff_mode_ ABSL_GUARDED_BY(diff_spinlock_) = DiffMode::kNone;
  // True between `BeginDiffInput` and `TakeDiffResult`.
  bool diff_input_begun_ ABSL_GUARDED_BY(diff_spinlock_) = false;
  bool diff_input_unparsable_ ABSL_GUARDED_BY(diff_spinlock_) = false;
  // Labels produced by the current input, with the recorded payloads (the
  // payloads are only kept in record mode).
  std::map<std::string, std::string> diff_actual_records_
      ABSL_GUARDED_BY(diff_spinlock_);
  // Expected label -> payload of the current input, if a decodable baseline
  // was received.
  std::optional<std::map<std::string, std::string>> diff_expected_records_
      ABSL_GUARDED_BY(diff_spinlock_);
  // Size of the received baseline container if it could not be decoded.
  std::optional<size_t> diff_undecodable_container_size_
      ABSL_GUARDED_BY(diff_spinlock_);
  std::vector<DiffMismatch> diff_mismatches_ ABSL_GUARDED_BY(diff_spinlock_);
  bool diff_failure_reported_ ABSL_GUARDED_BY(diff_spinlock_) = false;
};

struct ReproducerOutputLocation {
  std::string dir_path;
  enum class Type {
    kUnspecified,
    kUserSpecified,
    kTestUndeclaredOutputs,
    kReportToController
  };
  Type type = Type::kUnspecified;
};

ReproducerOutputLocation GetReproducerOutputLocation();

void PrintReproducerIfRequested(absl::FormatRawSink out, const FuzzTest& test,
                                const Configuration* configuration,
                                std::string reproducer_path);

extern void (*crash_handler_hook)();

template <typename Arg, size_t I, typename Tuple>
decltype(auto) GetDomainOrArbitrary(const Tuple& t) {
  if constexpr (I < std::tuple_size_v<Tuple>) {
    return std::get<I>(t);
  } else {
    return Arbitrary<std::decay_t<Arg>>();
  }
}

class FuzzTestExternalEngineAdaptor;

class FuzzTestFuzzerImpl : public FuzzTestFuzzer {
 public:
  explicit FuzzTestFuzzerImpl(
      const FuzzTest& test,
      std::unique_ptr<UntypedFixtureDriver> fixture_driver);
  ~FuzzTestFuzzerImpl();

 private:
  // TODO(fniksic): Refactor to reduce code complexity and improve readability.
  bool RunInUnitTestMode(const Configuration& configuration) override;

  // TODO(fniksic): Refactor to reduce code complexity and improve readability.
  bool RunInFuzzingMode(int* argc, char*** argv,
                        const Configuration& configuration) override;

  // Use the standard PRNG instead of absl::BitGen because Abseil doesn't
  // guarantee seed stability
  // (https://abseil.io/docs/cpp/guides/random#seed-stability).
  using PRNG = std::mt19937;
  using corpus_type = GenericDomainCorpusType;

  struct Input {
    corpus_type args;
    size_t depth = 0;
    absl::Duration run_time = absl::ZeroDuration();
  };
  struct RunResult {
    bool new_coverage;
    absl::Duration run_time;
  };

  void PopulateFromSeeds(const std::vector<std::string>& corpus_files);

  bool ReplayInputsIfAvailable(const Configuration& configuration);

  std::optional<std::vector<std::string>> GetFilesToReplay();

  std::optional<corpus_type> ReadReproducerToMinimize();

  absl::StatusOr<corpus_type> TryParse(absl::string_view data);

  void MutateValue(Input& input, absl::BitGenRef prng,
                   const domain_implementor::MutationMetadata& metadata);

  void UpdateCorpusDistribution();

  void MinimizeNonFatalFailureLocally(absl::BitGenRef prng);

  // Runs on `sample` and returns new coverage and run time. If there's new
  // coverage, outputs updated runtime stats. Additionally, if `write_to_file`
  // is true, tries to write the sample to a file.
  RunResult TrySample(const Input& sample, bool write_to_file = true);

  // Runs on `sample` and records it into the in-memory corpus if it finds new
  // coverage. If `write_to_file` is set, tries to write the corpus data to a
  // file when recording it. Updates the memory dictionary on new coverage, and
  // occasionally even if there is no new coverage.
  void TrySampleAndUpdateInMemoryCorpus(Input sample,
                                        bool write_to_file = true);

  // Iterates over inputs in `files` and calls `consume` on each input.
  // `consume` is a function that takes a file path, an optional blob index in
  // the file (for blob files with multiple blobs), and an input in the given
  // file at the given blob index (if applicable). When `timeout` is reached
  // before calling the `consume` on an input, the iteration stops and the rest
  // of the inputs won't be consumed.
  void ForEachInput(
      absl::Span<const std::string> files,
      absl::FunctionRef<void(absl::string_view file_path,
                             std::optional<int> blob_idx, Input input)>
          consume,
      absl::Duration timeout = absl::InfiniteDuration());

  // Returns true if we're in minimization mode.
  bool MinimizeCorpusIfInMinimizationMode(absl::BitGenRef prng);

  std::vector<Input> TryReadCorpusFromFiles();

  void TryWriteCorpusFile(const Input& input);

  void InitializeCorpus(absl::BitGenRef prng);

  RunResult RunOneInput(const Input& input);

  bool ShouldStop();

  // Prints a message indicating that we're replaying an input from `file_path`
  // at `blob_idx` (if applicable) and then runs `input`.
  void ReplayInput(absl::string_view file_path, std::optional<int> blob_idx,
                   const Input& input);

  const FuzzTest& test_;
  std::unique_ptr<UntypedFixtureDriver> fixture_driver_;
  UntypedDomain params_domain_;
  std::seed_seq seed_sequence_ = GetFromEnvOrMakeSeedSeq(std::cerr);
  ExecutionCoverage* execution_coverage_;
  CorpusCoverage corpus_coverage_;
  std::deque<Input> corpus_;
  // Corpus distribution is only used in Fuzzing mode.
  absl::discrete_distribution<> corpus_distribution_;

  absl::string_view corpus_out_dir_;
  RuntimeStats stats_{};
  std::optional<size_t> runs_limit_;
  absl::Time time_limit_ = absl::InfiniteFuture();
  std::optional<Input> minimal_non_fatal_counterexample_;

  Runtime& runtime_ = Runtime::instance();

#ifdef FUZZTEST_COMPATIBILITY_MODE
  friend class FuzzTestExternalEngineAdaptor;
#endif  // FUZZTEST_COMPATIBILITY_MODE
  // Defined in centipede_adaptor.cc
  friend class CentipedeFuzzerAdaptor;
  friend class CentipedeAdaptorRunnerCallbacks;
  friend class CentipedeAdaptorEngineCallbacks;
};

// A reproduction command template will include these placeholders. These
// placeholders then will be replaced by the proper test filter when creating
// the final reproduction command from the template.
inline constexpr absl::string_view kTestFilterPlaceholder = "$TEST_FILTER";
inline constexpr absl::string_view kExtraArgsPlaceholder = "$EXTRA_ARGS";

// Returns the name of a regression test that replays `test_name` on the
// crashing input at `crashing_input_path`.
absl::StatusOr<std::string> RegressionTestNameForCrashingInput(
    absl::string_view test_name, absl::string_view crashing_input_path);

}  // namespace internal
}  // namespace fuzztest

#endif  // FUZZTEST_FUZZTEST_INTERNAL_RUNTIME_H_
