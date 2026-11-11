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

#include "./centipede/diff_baseline.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/base/no_destructor.h"
#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/synchronization/mutex.h"
#include "absl/types/span.h"
#include "./centipede/environment.h"
#include "./centipede/execution_metadata.h"
#include "./centipede/runner_result.h"
#include "./centipede/stop.h"
#include "./common/defs.h"
#include "./common/hash.h"
#include "./common/logging.h"
#include "./common/remote_file.h"

namespace fuzztest::internal {

namespace {

// Maximum number of per-input log lines of each kind.
constexpr size_t kMaxPerInputLogLines = 20;

bool IsValidAbsoluteOrRemoteDir(std::string_view dir) {
  if (dir.empty()) return false;
  if (absl::StrContains(dir, "://")) return true;
  return std::filesystem::path(dir).is_absolute();
}

size_t DiffStats::Snapshot::* CounterForFlag(DiffStats::InputFlag flag) {
  switch (flag) {
    case DiffStats::InputFlag::kSent:
      return &DiffStats::Snapshot::baselines_sent;
    case DiffStats::InputFlag::kMissing:
      return &DiffStats::Snapshot::baselines_missing;
    case DiffStats::InputFlag::kAcknowledged:
      return &DiffStats::Snapshot::baselines_acknowledged;
    case DiffStats::InputFlag::kUnparsable:
      return &DiffStats::Snapshot::inputs_unparsable;
    case DiffStats::InputFlag::kUnparsableWithBaseline:
      return &DiffStats::Snapshot::unparsable_with_baseline;
    case DiffStats::InputFlag::kFailed:
      return &DiffStats::Snapshot::inputs_failed;
    case DiffStats::InputFlag::kMismatch:
      return &DiffStats::Snapshot::mismatches;
  }
  FUZZTEST_LOG(FATAL) << "Unknown DiffStats::InputFlag: "
                      << static_cast<int>(flag);
}

}  // namespace

bool IsDiffActive(const Environment& env) {
  return (env.fuzztest_diff_mode == "record" ||
          env.fuzztest_diff_mode == "validate") &&
         env.fuzztest_only_replay && !env.replay_crash &&
         !env.has_input_wildcards;
}

bool IsDiffRecord(const Environment& env) {
  return IsDiffActive(env) && env.fuzztest_diff_mode == "record";
}

bool IsDiffValidate(const Environment& env) {
  return IsDiffActive(env) && env.fuzztest_diff_mode == "validate";
}

bool IsSingleInputFailure(const BatchResult& result) {
  return result.IsInputFailure() &&
         result.failure_description() != kExecutionFailurePerBatchTimeout;
}

std::string DiffBaselineBinaryDir(const Environment& env) {
  return (std::filesystem::path(env.fuzztest_workdir_root) / "baseline" /
          env.fuzztest_binary_identifier)
      .string();
}

std::string DiffBaselineTestDir(const Environment& env) {
  return (std::filesystem::path(DiffBaselineBinaryDir(env)) / env.test_name)
      .string();
}

DiffStats& DiffStats::Global() {
  static absl::NoDestructor<DiffStats> stats;
  return *stats;
}

void DiffStats::Reset() {
  absl::MutexLock lock(mu_);
  snapshot_ = {};
  input_flags_.clear();
  warned_about_missing_diff_data_ = false;
}

DiffStats::Snapshot DiffStats::Get() const {
  absl::MutexLock lock(mu_);
  return snapshot_;
}

void DiffStats::AddExecution() {
  absl::MutexLock lock(mu_);
  ++snapshot_.executions;
}

void DiffStats::AddBaselineWritten() {
  absl::MutexLock lock(mu_);
  ++snapshot_.baselines_written;
}

void DiffStats::AddIoError() {
  absl::MutexLock lock(mu_);
  ++snapshot_.io_errors;
}

void DiffStats::AddIncompleteBatch() {
  absl::MutexLock lock(mu_);
  ++snapshot_.incomplete_batches;
}

size_t DiffStats::MarkInput(std::string_view hash, InputFlag flag) {
  const uint8_t bit = static_cast<uint8_t>(flag);
  absl::MutexLock lock(mu_);
  auto [it, inserted] = input_flags_.try_emplace(hash, bit);
  if (!inserted) {
    if ((it->second & bit) != 0) return 0;
    it->second |= bit;
  }
  return ++(snapshot_.*CounterForFlag(flag));
}

bool DiffStats::ShouldWarnAboutMissingDiffData() {
  absl::MutexLock lock(mu_);
  if (warned_about_missing_diff_data_) return false;
  warned_about_missing_diff_data_ = true;
  return true;
}

DiffBaselineStore::DiffBaselineStore(const Environment& env)
    : active_(IsDiffActive(env) &&
              IsValidAbsoluteOrRemoteDir(env.fuzztest_workdir_root)),
      record_(IsDiffRecord(env)),
      test_dir_(active_ ? DiffBaselineTestDir(env) : "") {}

std::string DiffBaselineStore::BaselinePath(std::string_view hash) const {
  return (std::filesystem::path(test_dir_) / hash).string();
}

std::optional<ByteArray> DiffBaselineStore::Lookup(std::string_view hash) {
  {
    absl::MutexLock lock(mu_);
    if (auto it = cache_.find(hash); it != cache_.end()) return it->second;
  }
  const std::string path = BaselinePath(hash);
  std::optional<ByteArray> result;
  if (RemotePathExists(path)) {
    if (RemotePathIsDirectory(path)) {
      FUZZTEST_LOG(ERROR) << "[diff] ERROR: baseline path is a directory, "
                             "expected a file: "
                          << path;
      DiffStats::Global().AddIoError();
      return std::nullopt;
    }
    ByteArray contents;
    const absl::Status status = RemoteFileGetContents(path, contents);
    if (!status.ok()) {
      FUZZTEST_LOG(ERROR) << "[diff] ERROR: failed to read baseline file "
                          << path << ": " << status;
      DiffStats::Global().AddIoError();
      return std::nullopt;
    }
    result = std::move(contents);
  }
  absl::MutexLock lock(mu_);
  cache_.emplace(hash, result);
  return result;
}

absl::Status DiffBaselineStore::Save(std::string_view hash,
                                     ByteSpan container) {
  return RemoteFileSetContents(BaselinePath(hash), container);
}

DiffBatch DiffBaselineStore::PrepareBatch(absl::Span<const ByteSpan> inputs) {
  DiffBatch batch;
  batch.hashes.reserve(inputs.size());
  if (!record_) {
    batch.metadata.resize(inputs.size());
  }
  for (size_t i = 0; i < inputs.size(); ++i) {
    batch.hashes.push_back(Hash(inputs[i]));
    if (record_) continue;
    std::optional<ByteArray> baseline = Lookup(batch.hashes.back());
    if (baseline.has_value()) {
      batch.metadata[i] = EncodeDiffEnvelope(DiffEnvelopeKind::kExpectations,
                                             /*cmp_data=*/{}, *baseline);
    }
  }
  return batch;
}

void DiffBaselineStore::ProcessBatchResult(
    const DiffBatch& batch, BatchResult& batch_result,
    std::optional<size_t> num_inputs_written) {
  DiffStats& stats = DiffStats::Global();
  const size_t n_written = std::min(
      num_inputs_written.value_or(batch.hashes.size()), batch.hashes.size());
  const auto had_baseline = [&batch](size_t i) {
    return i < batch.metadata.size() && !batch.metadata[i].empty();
  };
  if (!record_) {
    for (size_t i = 0; i < n_written; ++i) {
      stats.MarkInput(batch.hashes[i], had_baseline(i)
                                           ? DiffStats::InputFlag::kSent
                                           : DiffStats::InputFlag::kMissing);
    }
  }
  const size_t num_results =
      std::min({batch_result.num_outputs_read(), n_written,
                batch_result.results().size()});
  for (size_t i = 0; i < num_results; ++i) {
    ExecutionMetadata& metadata = batch_result.results()[i].metadata();
    DiffEnvelopeKind kind;
    ByteSpan cmp_data;
    ByteSpan payload;
    if (!DecodeDiffEnvelope(metadata.cmp_data, kind, cmp_data, payload) ||
        kind == DiffEnvelopeKind::kExpectations) {
      if (stats.ShouldWarnAboutMissingDiffData()) {
        FUZZTEST_LOG(WARNING)
            << "[diff] WARNING: worker returned no RecordOrDiff data for an "
               "executed input; is RecordOrDiff supported by this binary?";
      }
      continue;
    }
    const std::string& hash = batch.hashes[i];
    switch (kind) {
      case DiffEnvelopeKind::kRecords:
        stats.AddExecution();
        if (!record_) break;
        if (const absl::Status status = Save(hash, payload); status.ok()) {
          stats.AddBaselineWritten();
        } else {
          FUZZTEST_LOG(ERROR) << "[diff] ERROR: failed to write baseline file "
                              << BaselinePath(hash) << ": " << status;
          stats.AddIoError();
        }
        break;
      case DiffEnvelopeKind::kAck:
        stats.AddExecution();
        if (had_baseline(i)) {
          stats.MarkInput(hash, DiffStats::InputFlag::kAcknowledged);
        }
        break;
      case DiffEnvelopeKind::kSkippedUnparsable:
        stats.AddExecution();
        if (had_baseline(i)) {
          stats.MarkInput(hash, DiffStats::InputFlag::kUnparsableWithBaseline);
        }
        if (const size_t count =
                stats.MarkInput(hash, DiffStats::InputFlag::kUnparsable);
            count > 0 && count <= kMaxPerInputLogLines) {
          FUZZTEST_LOG(WARNING)
              << "[diff] WARNING: input " << hash
              << " could not be parsed by the current FUZZ_TEST domains; "
                 "RecordOrDiff skipped it";
        }
        break;
      case DiffEnvelopeKind::kExpectations:
        break;
    }
    // Copy the plain CMP slice before replacing `metadata.cmp_data`, since
    // `cmp_data` points into it.
    metadata.cmp_data = ByteArray(cmp_data.begin(), cmp_data.end());
  }
  if (batch_result.exit_code() != EXIT_SUCCESS) {
    if (IsSingleInputFailure(batch_result) &&
        batch_result.num_outputs_read() < n_written) {
      const std::string& hash = batch.hashes[batch_result.num_outputs_read()];
      stats.MarkInput(hash, DiffStats::InputFlag::kFailed);
      if (absl::StartsWith(batch_result.failure_description(),
                           kDiffMismatchFailurePrefix)) {
        if (const size_t count =
                stats.MarkInput(hash, DiffStats::InputFlag::kMismatch);
            count > 0 && count <= kMaxPerInputLogLines) {
          FUZZTEST_LOG(INFO) << "[diff] Mismatch for input " << hash
                             << "; baseline file " << BaselinePath(hash);
        }
      }
    } else if (!batch_result.IsIgnoredFailure() &&
               !batch_result.IsSkippedTest() &&
               batch_result.num_outputs_read() < batch.hashes.size()) {
      stats.AddIncompleteBatch();
    }
  }
}

void PrepareDiffBaselineForTest(const Environment& env,
                                StopCondition& stop_condition) {
  if (!env.fuzztest_diff_mode.empty() && env.fuzztest_diff_mode != "none" &&
      env.fuzztest_diff_mode != "record" &&
      env.fuzztest_diff_mode != "validate") {
    FUZZTEST_LOG(ERROR) << "[diff] ERROR: invalid --fuzztest_diff_mode='"
                        << env.fuzztest_diff_mode
                        << "'; must be one of: none, record, validate";
    stop_condition.RequestStop(EXIT_FAILURE, "Invalid --fuzztest_diff_mode");
    return;
  }
  if (!IsDiffActive(env)) return;
  DiffStats::Global().Reset();
  if (!IsValidAbsoluteOrRemoteDir(env.fuzztest_workdir_root)) {
    FUZZTEST_LOG(ERROR)
        << "[diff] ERROR: --fuzztest_workdir_root must be a non-empty "
           "absolute path when --fuzztest_diff_mode is enabled (got '"
        << env.fuzztest_workdir_root << "')";
    stop_condition.RequestStop(
        EXIT_FAILURE,
        "RecordOrDiff requires an absolute --fuzztest_workdir_root");
    return;
  }
  if (env.test_name.empty()) {
    FUZZTEST_LOG(ERROR) << "[diff] ERROR: --test_name must not be empty when "
                           "--fuzztest_diff_mode is enabled";
    stop_condition.RequestStop(EXIT_FAILURE,
                               "RecordOrDiff requires a non-empty test_name");
    return;
  }
  const std::string test_dir = DiffBaselineTestDir(env);
  if (IsDiffRecord(env)) {
    FUZZTEST_LOG(INFO) << "[diff] Recording baseline for " << env.test_name
                       << " into " << test_dir;
    // Start from scratch so that stale baselines cannot leak in.
    if (RemotePathExists(test_dir)) {
      FUZZTEST_CHECK_OK(RemotePathDelete(test_dir, /*recursively=*/true));
    }
    FUZZTEST_CHECK_OK(RemoteMkdir(test_dir));
    return;
  }
  FUZZTEST_LOG(INFO) << "[diff] Validating " << env.test_name
                     << " against baseline " << test_dir;
  const std::string binary_dir = DiffBaselineBinaryDir(env);
  if (!RemotePathExists(binary_dir)) {
    FUZZTEST_LOG(ERROR) << "[diff] ERROR: baseline directory " << binary_dir
                        << " does not exist; run --fuzztest_record with the "
                           "same --fuzztest_workdir_root first";
    stop_condition.RequestStop(EXIT_FAILURE,
                               "RecordOrDiff baseline directory is missing");
    return;
  }
  if (!RemotePathExists(test_dir)) {
    FUZZTEST_LOG(WARNING) << "[diff] WARNING: baseline directory " << test_dir
                          << " does not exist; every input will count as "
                             "baselines_missing";
  }
}

void FinishDiffForTest(const Environment& env, StopCondition& stop_condition) {
  if (!IsDiffActive(env)) return;
  const bool record = IsDiffRecord(env);
  const DiffStats::Snapshot stats = DiffStats::Global().Get();
  FUZZTEST_LOG(INFO) << "[diff] Summary for " << env.test_name
                     << ": mode=" << (record ? "record" : "validate")
                     << " executions=" << stats.executions
                     << " baselines_written=" << stats.baselines_written
                     << " baselines_sent=" << stats.baselines_sent
                     << " baselines_acknowledged="
                     << stats.baselines_acknowledged
                     << " baselines_missing=" << stats.baselines_missing
                     << " inputs_unparsable=" << stats.inputs_unparsable
                     << " inputs_failed=" << stats.inputs_failed
                     << " mismatches=" << stats.mismatches
                     << " io_errors=" << stats.io_errors
                     << " incomplete_batches=" << stats.incomplete_batches;
  bool failed = false;
  std::string failure_reason;
  if (stats.io_errors > 0) {
    FUZZTEST_LOG(ERROR) << "[diff] ERROR: " << stats.io_errors
                        << " baseline file I/O error(s) occurred for "
                        << env.test_name;
    failed = true;
    failure_reason = "RecordOrDiff baseline I/O error";
  }
  if (stats.incomplete_batches > 0) {
    FUZZTEST_LOG(ERROR) << "[diff] ERROR: " << stats.incomplete_batches
                        << " batch(es) of " << env.test_name
                        << " ended early leaving inputs unexecuted";
    failed = true;
    if (failure_reason.empty()) {
      failure_reason = "RecordOrDiff execution was incomplete";
    }
  }
  if (record) {
    if (stats.inputs_failed > 0) {
      // Fail the record run so that an incomplete baseline does not go
      // unnoticed.
      FUZZTEST_LOG(ERROR) << "[diff] ERROR: record of " << env.test_name
                          << " is incomplete because " << stats.inputs_failed
                          << " input(s) failed and have no baseline";
      failed = true;
      if (failure_reason.empty()) {
        failure_reason = "RecordOrDiff record had failing inputs";
      }
    }
  } else {
    if (stats.mismatches > 0) {
      FUZZTEST_LOG(ERROR) << "[diff] ERROR: " << stats.mismatches
                          << " input(s) of " << env.test_name
                          << " differ from the baseline";
      failed = true;
    }
    if (stats.unparsable_with_baseline > 0) {
      FUZZTEST_LOG(ERROR)
          << "[diff] ERROR: " << stats.unparsable_with_baseline
          << " input(s) of " << env.test_name
          << " have a baseline but could not be parsed by the current "
             "FUZZ_TEST domains (did the signature or domains change since "
             "record?)";
      failed = true;
    }
    if (stats.baselines_sent == 0 && stats.executions > 0) {
      FUZZTEST_LOG(WARNING)
          << "[diff] WARNING: no executed input of " << env.test_name
          << " had a baseline; was the baseline recorded from the same corpus "
             "database?";
    }
    if (failed && failure_reason.empty()) {
      failure_reason = "RecordOrDiff validation failed";
    }
  }
  if (failed && !stop_condition.StopRequested()) {
    stop_condition.RequestStop(EXIT_FAILURE, failure_reason);
  }
}

}  // namespace fuzztest::internal
