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

#include "./centipede/stats.h"

#include <algorithm>
#include <cinttypes>
#include <cstdint>
#include <limits>
#include <numeric>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/strings/str_format.h"
#include "absl/strings/substitute.h"
#include "absl/types/span.h"
#include "./centipede/environment.h"
#include "./centipede/logging.h"
#include "./centipede/remote_file.h"

namespace centipede {

// -----------------------------------------------------------------------------
//                               StatsReporter

StatsReporter::StatsReporter(const std::vector<Stats> &stats_vec,
                             const std::vector<Environment> &env_vec)
    : stats_vec_{stats_vec}, env_vec_{env_vec} {
  CHECK_EQ(stats_vec.size(), env_vec.size());
  for (size_t i = 0; i < env_vec.size(); ++i) {
    const auto &env = env_vec[i];
    group_to_indices_[env.experiment_name].push_back(i);
    // NOTE: This will overwrite repeatedly for all indices of each group,
    // but the value will be the same by construction in environment.cc.
    group_to_flags_[env.experiment_name] = env.experiment_flags;
  }
}

void StatsReporter::ReportCurrStats() {
  PreAnnounceFields(Stats::kFieldInfos);
  for (const Stats::FieldInfo &field_info : Stats::kFieldInfos) {
    SetCurrField(field_info);
    for (const auto &[group_name, group_indices] : group_to_indices_) {
      SetCurrGroup(env_vec_[group_indices.at(0)]);
      // Get the required stat fields into a vector `stat_values`.
      std::vector<uint64_t> stat_values;
      stat_values.reserve(group_indices.size());
      for (const auto idx : group_indices) {
        stat_values.push_back(stats_vec_.at(idx).*(field_info.field));
      }
      ReportCurrFieldSample(std::move(stat_values));
    }
  }
  ReportFlags(group_to_flags_);
  DoneFieldSamplesBatch();
}

// -----------------------------------------------------------------------------
//                               StatsLogger

void StatsLogger::PreAnnounceFields(
    std::initializer_list<Stats::FieldInfo> fields) {
  // Nothing to do: field names are logged together with every sample values.
}

void StatsLogger::SetCurrGroup(const Environment &master_env) {
  if (!master_env.experiment_name.empty())
    os_ << master_env.experiment_name << ": ";
}

void StatsLogger::SetCurrField(const Stats::FieldInfo &field_info) {
  os_ << field_info.description << ":\n";
}

void StatsLogger::ReportCurrFieldSample(std::vector<uint64_t> &&values) {
  // Print min/max/avg and the full sorted contents of `values`.
  std::sort(values.begin(), values.end());
  os_ << "min:\t" << values.front() << "\t";
  os_ << "max:\t" << values.back() << "\t";
  os_ << "avg:\t"
      << (std::accumulate(values.begin(), values.end(), 0.) /
          static_cast<double>(values.size()))
      << "\t";
  os_ << "--";
  for (const auto value : values) {
    os_ << "\t" << value;
  }
  os_ << "\n";
}

void StatsLogger::ReportFlags(const GroupToFlags &group_to_flags) {
  os_ << "Flags:\n";
  for (const auto &[group_name, group_flags] : group_to_flags) {
    os_ << group_name << ": " << group_flags << "\n";
  }
}

void StatsLogger::DoneFieldSamplesBatch() {
  LOG(INFO) << "Current stats:\n" << absl::StripAsciiWhitespace(os_.str());
  os_.clear();
}

// -----------------------------------------------------------------------------
//                           StatsCsvFileAppender

StatsCsvFileAppender::~StatsCsvFileAppender() {
  for (const auto &[group_name, file] : files_) {
    RemoteFileClose(file);
  }
}

void StatsCsvFileAppender::PreAnnounceFields(
    std::initializer_list<Stats::FieldInfo> fields) {
  if (!csv_header_.empty()) return;

  for (const auto &field : fields) {
    const std::string field_col_names =
        absl::Substitute("$0_Min,$0_Max,$0_Avg,", field.name);
    absl::StrAppend(&csv_header_, field_col_names);
  }
  absl::StrAppend(&csv_header_, "\n");
}

void StatsCsvFileAppender::SetCurrGroup(const Environment &master_env) {
  RemoteFile *&file = files_[master_env.experiment_name];
  if (file == nullptr) {
    const std::string filename =
        master_env.MakeFuzzingStatsPath(master_env.experiment_name);
    // TODO(ussuri): Append, not overwrite, so restarts keep accumulating.
    //  This will require writing the CSV header only if the file is brand new.
    file = RemoteFileOpen(filename, "w");
    CHECK(file != nullptr) << VV(filename);
    RemoteFileAppend(file, csv_header_);
  }
  curr_file_ = file;
}

void StatsCsvFileAppender::SetCurrField(const Stats::FieldInfo &field_info) {
  // Nothing to do: Field names are printed as the CSV header elsewhere.
}

void StatsCsvFileAppender::ReportCurrFieldSample(
    std::vector<uint64_t> &&values) {
  // Print min/max/avg of `values`.
  uint64_t min = std::numeric_limits<uint64_t>::max();
  uint64_t max = std::numeric_limits<uint64_t>::min();
  long double avg = 0;
  for (const auto value : values) {
    min = std::min(min, value);
    max = std::max(max, value);
    avg += value;
  }
  if (!values.empty()) avg /= values.size();
  const std::string str =
      absl::StrFormat("%" PRIu64 ",%" PRIu64 ",%.1Lf,", min, max, avg);
  RemoteFileAppend(curr_file_, str);
}

void StatsCsvFileAppender::ReportFlags(const GroupToFlags &group_to_flags) {
  // Do nothing: can't write to CSV, as it has no concept of comments.
  // TODO(ussuri): Consider writing to a sidecar file.
}

void StatsCsvFileAppender::DoneFieldSamplesBatch() {
  for (const auto &[group_name, file] : files_) {
    RemoteFileAppend(file, "\n");
  }
}

// -----------------------------------------------------------------------------

void PrintRewardValues(absl::Span<const Stats> stats_vec, std::ostream &os) {
  size_t n = stats_vec.size();
  CHECK_GT(n, 0);
  std::vector<size_t> num_covered_pcs(n);
  for (size_t i = 0; i < n; ++i) {
    num_covered_pcs[i] = stats_vec[i].num_covered_pcs;
  }
  std::sort(num_covered_pcs.begin(), num_covered_pcs.end());
  os << "REWARD_MAX " << num_covered_pcs.back() << "\n";
  os << "REWARD_SECOND_MAX " << num_covered_pcs[n == 1 ? 1 : n - 2] << "\n";
  os << "REWARD_MIN " << num_covered_pcs.front() << "\n";
  os << "REWARD_MEDIAN " << num_covered_pcs[n / 2] << "\n";
  os << "REWARD_AVERAGE "
     << (std::accumulate(num_covered_pcs.begin(), num_covered_pcs.end(), 0.) /
         n)
     << "\n";
}

}  // namespace centipede
