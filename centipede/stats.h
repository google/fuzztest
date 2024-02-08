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
#include <cstdlib>
#include <initializer_list>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_map.h"
#include "absl/types/span.h"
#include "./centipede/environment.h"
#include "./centipede/remote_file.h"

namespace centipede {

// A set of statistics about the fuzzing progress.
// Each worker thread has its own Stats object and updates it periodically.
// The updates must not be frequent for performance reasons.
// All such objects may be read synchronously by another thread,
// hence the use of atomics.
// These objects may also be accessed after all worker threads have joined.
// TODO(ussuri): Too many atomics now: danger of grabbing stats half-way
//  through updating in centipede.cc. Replace with a mutex instead.
struct Stats {
  std::atomic<uint64_t> timestamp_unix_micros = 0;

  // Performance.
  std::atomic<uint64_t> fuzz_time_sec = 0;
  std::atomic<uint64_t> num_executions = 0;
  std::atomic<uint64_t> num_target_crashes = 0;

  // Coverage.
  std::atomic<uint64_t> num_covered_pcs = 0;
  std::atomic<uint64_t> num_8bit_counter_features = 0;
  std::atomic<uint64_t> num_data_flow_features = 0;
  std::atomic<uint64_t> num_cmp_features = 0;
  std::atomic<uint64_t> num_call_stack_features = 0;
  std::atomic<uint64_t> num_bounded_path_features = 0;
  std::atomic<uint64_t> num_pc_pair_features = 0;
  std::atomic<uint64_t> num_user_features = 0;
  std::atomic<uint64_t> num_unknown_features = 0;
  std::atomic<uint64_t> num_funcs_in_frontier = 0;

  // Corpus & element sizes.
  std::atomic<uint64_t> active_corpus_size = 0;
  std::atomic<uint64_t> total_corpus_size = 0;
  std::atomic<uint64_t> max_corpus_element_size = 0;
  std::atomic<uint64_t> avg_corpus_element_size = 0;

  // Rusage.
  std::atomic<uint64_t> engine_rusage_avg_millicores = 0;
  std::atomic<uint64_t> engine_rusage_cpu_percent = 0;
  std::atomic<uint64_t> engine_rusage_rss_mb = 0;
  std::atomic<uint64_t> engine_rusage_vsize_mb = 0;

  using Traits = uint32_t;
  enum TraitBits : Traits {
    // The kind of the stat.
    kTimestamp = 1UL << 0,
    kFuzzStat = 1UL << 1,
    kRUsageStat = 1UL << 2,

    // The aggregate value(s) to report for the stat.
    kMin = 1UL << 8,
    kMax = 1UL << 9,
    kAvg = 1UL << 10,
    kSum = 1UL << 11,
  };

  // Ascribes some properties to each stat. Used in `StatReporter` & subclasses.
  struct FieldInfo {
    std::atomic<uint64_t> Stats::*field;
    // The machine-readable name of the field. Used in the CSV header.
    std::string_view name;
    // The human-readable description of the field. Used in logging.
    std::string_view description;
    Traits traits;
  };

  // WARNING!!! Before reordering these or changing the aggregation types,
  // consider the backward compatibility implications for historical CSVs out
  // there: if some end-user has a CSV post-processing step that relies on the
  // old order or the aggregation type of the CSV fields, that step will break
  // if either of those things change; if the post-processing step relies on the
  // field names in the CSV header, than might break if those names change; etc.
  // In other words: do not change the names or the order of the old fields
  // without a very good reason.
  static constexpr std::initializer_list<FieldInfo> kFieldInfos = {
      {
          &Stats::num_covered_pcs,
          "NumCoveredPcs",
          "Coverage",
          kFuzzStat | kMin | kMax | kAvg,
      },
      {
          &Stats::num_executions,
          "NumExecs",
          "Number of executions",
          kFuzzStat | kMin | kMax | kAvg,
      },
      {
          &Stats::active_corpus_size,
          "ActiveCorpusSize",
          "Active corpus size",
          kFuzzStat | kMin | kMax | kAvg,
      },
      {
          &Stats::max_corpus_element_size,
          "MaxEltSize",
          "Max element size",
          kFuzzStat | kMin | kMax | kAvg,
      },
      {
          &Stats::avg_corpus_element_size,
          "AvgEltSize",
          "Avg element size",
          kFuzzStat | kMin | kMax | kAvg,
      },
      {
          &Stats::timestamp_unix_micros,
          "UnixMicros",
          "Timestamp",
          kTimestamp | kMin | kMax,
      },
      {
          &Stats::fuzz_time_sec,
          "FuzzTimeSec",
          "Fuzz time (sec)",
          kFuzzStat | kMin | kMax | kAvg,
      },
      {
          &Stats::num_target_crashes,
          "NumProxyCrashes",
          "Num proxy crashes",
          kFuzzStat | kMin | kMax | kSum,
      },
      {
          &Stats::total_corpus_size,
          "TotalCorpusSize",
          "Total corpus size",
          kFuzzStat | kMin | kMax | kSum,
      },
      {
          &Stats::num_8bit_counter_features,
          "Num8BitCounterFts",
          "Num 8-bit counter features",
          kFuzzStat | kMin | kMax | kAvg,
      },
      {
          &Stats::num_data_flow_features,
          "NumDataFlowFts",
          "Num data flow features",
          kFuzzStat | kMin | kMax | kAvg,
      },
      {
          &Stats::num_cmp_features,
          "NumCmpFts",
          "Num cmp features",
          kFuzzStat | kMin | kMax | kAvg,
      },
      {
          &Stats::num_call_stack_features,
          "NumCallStackFts",
          "Num call stack features",
          kFuzzStat | kMin | kMax | kAvg,
      },
      {
          &Stats::num_bounded_path_features,
          "NumBoundedPathFts",
          "Num bounded path features",
          kFuzzStat | kMin | kMax | kAvg,
      },
      {
          &Stats::num_pc_pair_features,
          "NumPcPairFts",
          "Num PC pair features",
          kFuzzStat | kMin | kMax | kAvg,
      },
      {
          &Stats::num_user_features,
          "NumUserFts",
          "Num user features",
          kFuzzStat | kMin | kMax | kAvg,
      },
      {
          &Stats::num_unknown_features,
          "NumUnknownFts",
          "Num unknown features",
          kFuzzStat | kMin | kMax | kAvg,
      },
      {
          &Stats::num_funcs_in_frontier,
          "NumFuncsInFrontier",
          "Num funcs in frontier",
          kFuzzStat | kMin | kMax | kAvg,
      },
      // Rusage. Each shard of a run is a thread of the same process, but it
      // measures the following metrics for the whole process. That means that
      // all the shards should return more or less the same number for the same
      // thing, sampling jitter and noise notwithstanding. Therefore, for the
      // aggregate stat we use the upper bound of the samples.
      // TODO(ussuri): Revise aggregation for CPU metrics once/if we start
      // measuring them per-thread.
      {
          &Stats::engine_rusage_avg_millicores,
          "EngineRusageAvgCores",
          "Engine rusage avg cores",
          kRUsageStat | kMax,
      },
      {
          &Stats::engine_rusage_cpu_percent,
          "EngineRusageCpuPct",
          "Engine rusage CPU %",
          kRUsageStat | kMax,
      },
      {
          &Stats::engine_rusage_rss_mb,
          "EngineRusageRssMb",
          "Engine rusage RSS (MB)",
          kRUsageStat | kMax,
      },
      {
          &Stats::engine_rusage_vsize_mb,
          "EngineRusageVSizeMb",
          "Engine rusage VSize (MB)",
          kRUsageStat | kMax,
      },
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
  using GroupToIndices =  //
      absl::btree_map<std::string /*group_name*/,
                      std::vector<size_t> /*indices*/>;
  using GroupToFlags =
      absl::btree_map<std::string /*group_name*/, std::string /*flags*/>;

  // Substeps of the Template Method pattern, which is implemented in
  // `ReportCurrStats()`, that subclasses need to override to implement their
  // stats reporting.

  // Should this field be reported or skipped for the particular type of
  // reporting that the subclass does. Can use `field.traits` to determine that.
  virtual bool ShouldReportThisField(const Stats::FieldInfo &field) {
    return true;
  }
  // Gives a chance to subclasses to learn ahead of time the fields for which
  // samples are going to be reported, in this order. Is called once.
  virtual void PreAnnounceFields(
      std::initializer_list<Stats::FieldInfo> fields) = 0;
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
};

// Takes a set of `Stats` objects and a corresponding set of `Environment`
// objects and logs the current `Stats` values to LOG(INFO) on each invocation
// of `ReportCurrStats()`. If the environments indicate the use of the
// --experiment flag, the stats for each of the experiment are juxtaposed for
// easy visual comparison.
class StatsLogger : public StatsReporter {
 public:
  using StatsReporter::StatsReporter;
  ~StatsLogger() override = default;

 private:
  bool ShouldReportThisField(const Stats::FieldInfo &field) override;
  void PreAnnounceFields(
      std::initializer_list<Stats::FieldInfo> fields) override;
  void SetCurrGroup(const Environment &master_env) override;
  void SetCurrField(const Stats::FieldInfo &field_info) override;
  void ReportCurrFieldSample(std::vector<uint64_t> &&values) override;
  void DoneFieldSamplesBatch() override;
  void ReportFlags(const GroupToFlags &group_to_flags) override;

  std::stringstream os_;
  std::string curr_experiment_name_;
  Stats::FieldInfo curr_field_info_;
};

// Takes a set of `Stats` objects and a corresponding set of `Environment`
// objects `env_vec` and appends aggregate metrics of the current `Stats` values
// to a CSV file on each invocation of `ReportCurrStats()`. If the environments
// indicate the use of the --experiment flag, the stats for each of the
// experiments are written to a separate correspondingly named CSV file. The
// names of each output field are written to the file(s) as a CSV header.
//
// When the file already exists (e.g. Centipede runs in a previously populated
// workdir):
// - If the current CSV header matches the one in the file, then new CSV lines
//   will be appended to the file.
// - If the current CSV header doesn't match the one in the file (e.g. the
//   Centipede version changed and the set of CSV fields changed with it), then
//   the existing file will be renamed to `GetBackupFilename(filename)`, and a
//   new file will be created from scratch.
class StatsCsvFileAppender : public StatsReporter {
 public:
  using StatsReporter::StatsReporter;
  ~StatsCsvFileAppender() override;

 private:
  void PreAnnounceFields(
      std::initializer_list<Stats::FieldInfo> fields) override;
  void SetCurrGroup(const Environment &master_env) override;
  void SetCurrField(const Stats::FieldInfo &field_info) override;
  void ReportCurrFieldSample(std::vector<uint64_t> &&values) override;
  void DoneFieldSamplesBatch() override;
  void ReportFlags(const GroupToFlags &group_to_flags) override;

  // Given a filename, should return a backup file filename for it. The default
  // version appends the current timestamp as UNIX seconds. Intended for tests.
  virtual std::string GetBackupFilename(const std::string &filename) const;

  std::string csv_header_;
  absl::flat_hash_map<std::string /*group_name*/, RemoteFile *> files_;
  RemoteFile *curr_file_;
  Stats::FieldInfo curr_field_info_;
};

// Takes a span of Stats objects `stats_vec` and prints a summary of the results
// to `os`, such that it can be ingested as a reward function by an ML system.
// To be used with knobs.
void PrintRewardValues(absl::Span<const Stats> stats_vec, std::ostream& os);

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_STATS_H_
