// Copyright 2022 The Centipede Authors.
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

#ifndef THIRD_PARTY_CENTIPEDE_EXECUTION_RESULT_H_
#define THIRD_PARTY_CENTIPEDE_EXECUTION_RESULT_H_

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#include "./centipede/execution_metadata.h"
#include "./centipede/feature.h"
#include "./centipede/shared_memory_blob_sequence.h"

namespace centipede::runner_result {

inline constexpr std::string_view kExecutionFailurePerInputTimeout =
    "per-input-timeout-exceeded";
inline constexpr std::string_view kExecutionFailurePerBatchTimeout =
    "per-batch-timeout-exceeded";
inline constexpr std::string_view kExecutionFailureRssLimitExceeded =
    "rss-limit-exceeded";

// It represents the results of the execution of one input by the runner.
class ExecutionResult {
 public:
  // Movable, not Copyable.
  ExecutionResult(ExecutionResult&& other) = default;
  ExecutionResult& operator=(ExecutionResult&& other) = default;

  ExecutionResult() = default;
  explicit ExecutionResult(FeatureVec features)
      : features_(std::move(features)) {}

  // Execution statistics.
  struct Stats {
    uint64_t prep_time_usec = 0;  // Time taken to prepare for execution.
    uint64_t exec_time_usec = 0;  // Time taken to execute the input.
    uint64_t post_time_usec = 0;  // Time taken to post-process the coverage.
    uint64_t peak_rss_mb = 0;     // Peak RSS in Mb after executing the input.

    // For tests.
    bool operator==(const Stats& other) const {  // = default in C++20.
      return prep_time_usec == other.prep_time_usec &&
             exec_time_usec == other.exec_time_usec &&
             peak_rss_mb == other.peak_rss_mb &&
             post_time_usec == other.post_time_usec;
    }
  };

  // Accessors.
  const FeatureVec& features() const { return features_; }
  FeatureVec& mutable_features() { return features_; }
  const Stats& stats() const { return stats_; }
  Stats& stats() { return stats_; }
  const ExecutionMetadata& metadata() const { return metadata_; }
  ExecutionMetadata& metadata() { return metadata_; }

  // Clears the data, but doesn't deallocate the heap storage.
  void clear() {
    features_.clear();
    metadata_ = {};
    stats_ = {};
  }

 private:
  FeatureVec features_;  // Features produced by the target on one input.

  ExecutionMetadata metadata_;  // Metadata from executing one input.

  Stats stats_;  // Stats from executing one input.
};

// BatchResult is the communication API between Centipede and its runner.
// In consists of a vector of ExecutionResult objects, one per executed input,
// and optionally some other details about the execution of the input batch.
//
// The runner uses static methods Write*() to write to a blobseq.
// Centipede uses Read() to get all the data from blobseq.
class BatchResult {
 public:
  // If BatchResult is used in a hot loop, define it outside the loop and
  // use ClearAndResize() on every iteration.
  // This will reduce the number of mallocs.
  BatchResult() = default;

  // Not movable.
  BatchResult(BatchResult&& other) = delete;
  BatchResult& operator=(BatchResult&& other) = delete;

  // Clears all data, but usually does not deallocate heap storage.
  void ClearAndResize(size_t new_size) {
    for (auto& result : results_) result.clear();
    results_.resize(new_size);
    log_.clear();
    exit_code_ = EXIT_SUCCESS;
    num_outputs_read_ = 0;
  }

  // Writes one FeatureVec (from `vec` and `size`) to `blobseq`.
  // Returns true iff successful.
  // Called by the runner.
  // When executing N inputs, the runner will call this at most N times.
  static bool WriteOneFeatureVec(const feature_t* vec, size_t size,
                                 BlobSequence& blobseq);
  // Writes a special Begin marker before executing an input.
  static bool WriteInputBegin(BlobSequence& blobseq);
  // Writes a special End marker after executing an input.
  static bool WriteInputEnd(BlobSequence& blobseq);
  // Writes unit execution stats.
  static bool WriteStats(const ExecutionResult::Stats& stats,
                         BlobSequence& blobseq);
  // Writes the execution `metadata` to `blobseq`.
  // Returns true iff successful.
  static bool WriteMetadata(const ExecutionMetadata& metadata,
                            BlobSequence& blobseq);

  // Reads everything written by the runner to `blobseq` into `this`.
  // Returns true iff successful.
  // When running N inputs, ClearAndResize(N) must be called before Read().
  bool Read(BlobSequence& blobseq);

  // Accessors.
  std::vector<ExecutionResult>& results() { return results_; }
  const std::vector<ExecutionResult>& results() const { return results_; }
  std::string& log() { return log_; }
  const std::string& log() const { return log_; }
  int& exit_code() { return exit_code_; }
  int exit_code() const { return exit_code_; }
  size_t num_outputs_read() const { return num_outputs_read_; }
  size_t& num_outputs_read() { return num_outputs_read_; }
  std::string& failure_description() { return failure_description_; }
  const std::string& failure_description() const {
    return failure_description_;
  }

 private:
  friend class MultiInputMock;

  std::vector<ExecutionResult> results_;
  std::string log_;  // log_ is populated optionally, e.g. if there was a crash.
  int exit_code_ = EXIT_SUCCESS;  // Process exit code.
  std::string failure_description_;
  size_t num_outputs_read_ = 0;
};

// Write a generated (either a mutant or seed) input data to `blobseq`. Returns
// true on success, false otherwise.
bool WriteInputData(ByteSpan data, BlobSequence& blobseq);

// Write the number of available seeds to `blobseq`. Returns true on success,
// false otherwise.
bool WriteNumAvailSeeds(size_t num_avail_seeds, BlobSequence& blobseq);

// Returns true iff `blob` indicates an input data written from
// `WriteInputData`.
bool IsInputData(Blob blob);

// Returns true and sets `num_avail_seeds`
// iff the blob indicates the number of seeds written from `WriteNumAvailSeeds`.
bool IsNumAvailSeeds(Blob blob, size_t& num_avail_seeds);

}  // namespace centipede::runner_result

#endif  // THIRD_PARTY_CENTIPEDE_EXECUTION_RESULT_H_
