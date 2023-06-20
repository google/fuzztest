#include "absl/container/flat_hash_map.h"
#include "absl/time/clock.h"
#include "./centipede/remote_file.h"
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

#ifndef THIRD_PARTY_CENTIPEDE_STATS_H_
#define THIRD_PARTY_CENTIPEDE_STATS_H_

#include <atomic>
#include <cstdint>
#include <initializer_list>
#include <map>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>

#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./centipede/environment.h"

namespace centipede {

// A set of statistics about the fuzzing progress.
// Each worker thread has its own Stats object and updates it periodically.
// The updates must not be frequent for performance reasons.
// All such objects may be read synchronously by another thread,
// hence the use of atomics.
// These objects may also be accessed after all worker threads have joined.
struct Stats {
  std::atomic<uint64_t> num_executions;
  std::atomic<uint64_t> num_covered_pcs;
  std::atomic<uint64_t> corpus_size;
  std::atomic<uint64_t> max_corpus_element_size;
  std::atomic<uint64_t> avg_corpus_element_size;

  struct FieldInfo {
    std::atomic<uint64_t> Stats::*field;
    std::string_view name;
    std::string_view description;
  };

  static constexpr std::initializer_list<FieldInfo> kFieldInfos = {
      {&Stats::num_executions, "NumExecs", "Number of executions"},
      {&Stats::num_covered_pcs, "NumCoveredPcs", "Coverage"},
      {&Stats::corpus_size, "CorpusSize", "Corpus size"},
      {&Stats::max_corpus_element_size, "MaxEltSize", "Max element size"},
      {&Stats::avg_corpus_element_size, "AvgEltSize", "Avg element size"},
  };
};

// An abstract stats reporter. Observes an external set of `Stats` objects and a
// matching set of `Environment` objects, assumed to be updated regularly by the
// owning scope to reflect the current execution numbers. Reports these current
// numbers to an abstract report sink whenever the owning scope invokes
// `ReportCurrStats()`. Concrete report sinks are implemented by inheriting
// classes by overriding the virtual API.
class StatsReporter {
 public:
  StatsReporter(const std::vector<Stats> &stats_vec,
                const std::vector<Environment> &env_vec);

  virtual ~StatsReporter() = default;

  // Reports the current sample of stats values as updated in the `stats_vec_`
  // externally by the caller. Implements the Template Method pattern by
  // invoking the private virtual APIs below in the right order and with the
  // right data to create a complete sample report.
  void ReportCurrStats();

 protected:
  using GroupToIndices =
      std::map<std::string /*group_name*/, std::vector<size_t> /*indices*/>;
  using GroupToFlags =
      std::map<std::string /*group_name*/, std::string /*flags*/>;

  // Substeps of the Template Method pattern, which is implemented in
  // `ReportCurrStats()`, that subclasses need to override to implement their
  // stats reporting.

  // Gives a chance to subclasses to learn ahead of time the properties of the
  // sampled shard groups, e.g. experiments (--experiment). Is called once.
  virtual void PreAnnounceGroups(
      const std::vector<const Environment *> &master_envs) = 0;
  // Gives a chance to subclasses to learn ahead of time the fields for which
  // samples are going to be reported, in this order. Is called once.
  virtual void PreAnnounceFields(
      std::initializer_list<Stats::FieldInfo> fields) = 0;
  // Starts a new batch of field samples. Is called once per batch. `timestamp`
  // is the approximate time when all the samples in the batch have been taken.
  virtual void StartFieldSamplesBatch(absl::Time timestamp) = 0;
  // Selects the group for the next batch of `ReportCurrFieldSample()` calls.
  virtual void SetCurrGroup(const Environment &master_env) = 0;
  // Selects the field for the next batch of `ReportCurrFieldSample()` calls.
  // Each of those calls will follow a unique combination of `SetCurrGroup()`
  // and `SetCurrField()`.
  virtual void SetCurrField(const Stats::FieldInfo &field_info) = 0;
  // Reports the values for the current group/field selected via the above two
  // calls.
  virtual void ReportCurrFieldSample(std::vector<uint64_t> &&values) = 0;
  // Wraps up the current field sample batch.
  virtual void DoneFieldSamplesBatch() = 0;
  // Gives subclasses an option to report the flags associated with each shard
  // group (e.g. experiments).
  virtual void ReportFlags(const GroupToFlags &group_to_flags) = 0;

 private:
  // Cached external sets of stats and environments to observe.
  const std::vector<Stats> &stats_vec_;
  const std::vector<Environment> &env_vec_;

  // Maps group names to indices in `env_vec_` / `stats_vec_`. If there is
  // just a single run (no groups), it will be stored in a single "" key.
  // NOTE: Use std::map to order groups lexicographically.
  GroupToIndices group_to_indices_;
  // Maps group names to their distinct flags (stringified). If there is
  // just a single run (no groups), it will be stored in a single "" key.
  // NOTE: Use std::map to order groups lexicographically.
  GroupToFlags group_to_flags_;

  // Set to true after the `PreAnnounce*()` virtual overrides are called once.
  bool init_done_ = false;
};

// Takes a set of `Stats` objects and a corresponding set of `Environment`
// objects `env_vec` and logs the current `Stats` values to LOG(INFO) on each
// invocation of `ReportCurrStats()`. If the environments indicate the use of
// the --experiment flag, the stats for each of the experiment are juxtaposed
// for easy visual comparison.
class StatsLogger : public StatsReporter {
 public:
  using StatsReporter::StatsReporter;
  ~StatsLogger() override = default;

 private:
  void PreAnnounceGroups(
      const std::vector<const Environment *> &master_envs) override;
  void PreAnnounceFields(
      std::initializer_list<Stats::FieldInfo> fields) override;
  void StartFieldSamplesBatch(absl::Time timestamp) override;
  void SetCurrGroup(const Environment &master_env) override;
  void SetCurrField(const Stats::FieldInfo &field_info) override;
  void ReportCurrFieldSample(std::vector<uint64_t> &&values) override;
  void DoneFieldSamplesBatch() override;
  void ReportFlags(const GroupToFlags &group_to_flags) override;

  std::stringstream os_;
};

class StatsCsvFileAppender : public StatsReporter {
 public:
  using StatsReporter::StatsReporter;
  ~StatsCsvFileAppender() override;

 private:
  void PreAnnounceGroups(
      const std::vector<const Environment *> &master_envs) override;
  void PreAnnounceFields(
      std::initializer_list<Stats::FieldInfo> fields) override;
  void StartFieldSamplesBatch(absl::Time timestamp) override;
  void SetCurrGroup(const Environment &master_env) override;
  void SetCurrField(const Stats::FieldInfo &field_info) override;
  void ReportCurrFieldSample(std::vector<uint64_t> &&values) override;
  void DoneFieldSamplesBatch() override;
  void ReportFlags(const GroupToFlags &group_to_flags) override;

  std::string csv_header_;
  absl::flat_hash_map<std::string /*group_name*/, RemoteFile *> files_;
  RemoteFile *curr_file_;
  absl::Time start_time_ = absl::Now();
};

// Takes a span of Stats objects `stats_vec` and prints a summary of the results
// to `os`, such that it can be ingested as a reward function by an ML system.
// To be used with knobs.
void PrintRewardValues(absl::Span<const Stats> stats_vec, std::ostream& os);

}  // namespace centipede
#endif  // THIRD_PARTY_CENTIPEDE_STATS_H_
