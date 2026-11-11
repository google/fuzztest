// Copyright 2026 The Centipede Authors.
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

// Controller-side support for incremental differential fuzzing
// (`fuzztest::RecordOrDiff`).
//
// The baseline of a fuzz test is stored by the controller at
//
//   <fuzztest_workdir_root>/baseline/<fuzztest_binary_identifier>/<test>/<hash>
//
// where <hash> is `Hash()` of the exact input bytes and the file content is the
// record container produced by the runner (opaque to Centipede). All file I/O
// of the feature happens here, in the controller; the runner never touches
// these paths.

#ifndef FUZZTEST_CENTIPEDE_DIFF_BASELINE_H_
#define FUZZTEST_CENTIPEDE_DIFF_BASELINE_H_

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/span.h"
#include "./centipede/environment.h"
#include "./centipede/runner_result.h"
#include "./centipede/stop.h"
#include "./common/defs.h"

namespace fuzztest::internal {

// The failure description prefix of RecordOrDiff mismatch findings.
inline constexpr std::string_view kDiffMismatchFailurePrefix =
    "RecordOrDiff mismatch";

// Returns true iff the incremental differential fuzzing is active for `env`.
bool IsDiffActive(const Environment& env);
bool IsDiffRecord(const Environment& env);
bool IsDiffValidate(const Environment& env);

// Returns true iff `result` represents a failure attributable to a single
// executed input (as opposed to setup failures, skipped tests, or per-batch
// timeouts).
bool IsSingleInputFailure(const BatchResult& result);

// Returns `<fuzztest_workdir_root>/baseline/<fuzztest_binary_identifier>`.
std::string DiffBaselineBinaryDir(const Environment& env);

// Returns `<fuzztest_workdir_root>/baseline/<binary id>/<test_name>`.
std::string DiffBaselineTestDir(const Environment& env);

// Counters of the incremental differential fuzzing of the current test,
// shared by all shards of the controller process. Reset by
// `PrepareDiffBaselineForTest`, so they are per-test as long as the tests of a
// controller run sequentially.
class DiffStats {
 public:
  struct Snapshot {
    // Results with a well-formed envelope (counting re-executions).
    size_t executions = 0;
    // Baseline file writes (counting overwrites).
    size_t baselines_written = 0;
    // Baseline file read or write I/O errors.
    size_t io_errors = 0;
    // Batches that ended early without a single-input failure (e.g. per-batch
    // timeout or setup failure) leaving inputs unexecuted.
    size_t incomplete_batches = 0;
    // The following count distinct inputs.
    size_t baselines_sent = 0;
    size_t baselines_acknowledged = 0;
    size_t baselines_missing = 0;
    size_t inputs_unparsable = 0;
    size_t inputs_failed = 0;
    size_t mismatches = 0;
    // Inputs that were sent a baseline but were unparsable.
    size_t unparsable_with_baseline = 0;
  };

  enum class InputFlag : uint8_t {
    kSent = 1 << 0,
    kMissing = 1 << 1,
    kAcknowledged = 1 << 2,
    kUnparsable = 1 << 3,
    kUnparsableWithBaseline = 1 << 4,
    kFailed = 1 << 5,
    kMismatch = 1 << 6,
  };

  static DiffStats& Global();

  void Reset();
  Snapshot Get() const;

  void AddExecution();
  void AddBaselineWritten();
  void AddIoError();
  void AddIncompleteBatch();
  // Records `flag` for `hash` if not already set. Returns the new count for
  // `flag`, or 0 if `hash` was already recorded for `flag`.
  size_t MarkInput(std::string_view hash, InputFlag flag);
  // Returns true only for the first call after Reset().
  bool ShouldWarnAboutMissingDiffData();

 private:
  mutable absl::Mutex mu_;
  Snapshot snapshot_ ABSL_GUARDED_BY(mu_);
  absl::flat_hash_map<std::string, uint8_t> input_flags_ ABSL_GUARDED_BY(mu_);
  bool warned_about_missing_diff_data_ ABSL_GUARDED_BY(mu_) = false;
};

// Per-batch bookkeeping between `PrepareBatch` and `ProcessBatchResult`.
struct DiffBatch {
  // Per-input hashes of the input bytes.
  std::vector<std::string> hashes;
  // Validate mode: per-input metadata blobs to send (envelope with the
  // baseline, or empty if the input has no baseline). Record mode: empty.
  std::vector<ByteArray> metadata;
};

// Reads and writes the baseline files of the current test. Used by
// `CentipedeCallbacks` when executing inputs.
class DiffBaselineStore {
 public:
  explicit DiffBaselineStore(const Environment& env);

  bool active() const { return active_; }

  // Returns the baseline record container of the input with `hash`, or nullopt
  // if there is none. Caches the result.
  std::optional<ByteArray> Lookup(std::string_view hash);

  // Writes the baseline record container of the input with `hash`.
  absl::Status Save(std::string_view hash, ByteSpan container);

  // Computes the hashes and (in validate mode) the metadata to send for
  // `inputs`.
  DiffBatch PrepareBatch(absl::Span<const ByteSpan> inputs);

  // Strips the diff envelopes from the results in `batch_result` (restoring
  // the plain CMP metadata), persists records (record mode), and updates the
  // counters for the `num_inputs_written` inputs actually written to shared
  // memory (defaults to all `batch.hashes.size()` inputs). Must be called for
  // every executed batch, on every return path.
  void ProcessBatchResult(
      const DiffBatch& batch, BatchResult& batch_result,
      std::optional<size_t> num_inputs_written = std::nullopt);

 private:
  std::string BaselinePath(std::string_view hash) const;

  const bool active_;
  const bool record_;
  const std::string test_dir_;
  absl::Mutex mu_;
  absl::flat_hash_map<std::string, std::optional<ByteArray>> cache_
      ABSL_GUARDED_BY(mu_);
};

// Called once per test before fuzzing (replaying) in the diff mode: resets
// `DiffStats`; record mode recreates the test's baseline directory; validate
// mode checks that the baseline directories exist and requests a failing stop
// if the binary's baseline directory is missing.
void PrepareDiffBaselineForTest(const Environment& env,
                                StopCondition& stop_condition);

// Called once per test at the end of the diff mode: prints the summary and
// requests a failing stop if the validation failed (mismatches or unparsable
// inputs with a baseline) or if inputs failed during record.
void FinishDiffForTest(const Environment& env, StopCondition& stop_condition);

}  // namespace fuzztest::internal

#endif  // FUZZTEST_CENTIPEDE_DIFF_BASELINE_H_
