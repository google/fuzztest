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
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <iomanip>
#include <ios>
#include <iosfwd>
#include <limits>
#include <numeric>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./centipede/environment.h"
#include "./centipede/logging.h"
#include "./centipede/remote_file.h"
#include "./centipede/workdir.h"

namespace centipede {

using TraitBits = Stats::TraitBits;

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
    if (!ShouldReportThisField(field_info)) continue;
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

bool StatsLogger::ShouldReportThisField(const Stats::FieldInfo &field) {
  return (field.traits & (TraitBits::kFuzzStat | TraitBits::kTimestamp)) != 0;
}

void StatsLogger::PreAnnounceFields(
    std::initializer_list<Stats::FieldInfo> fields) {
  // Nothing to do: field names are logged together with every sample's values.
}

void StatsLogger::SetCurrGroup(const Environment &master_env) {
  curr_experiment_name_ = master_env.experiment_name;
}

void StatsLogger::SetCurrField(const Stats::FieldInfo &field_info) {
  curr_field_info_ = field_info;
  os_ << curr_field_info_.description << ":\n";
}

namespace {
std::string FormatTimestamp(uint64_t unix_micros) {
  return absl::FormatTime("%Y-%m-%d%ET%H:%M:%S",
                          absl::FromUnixMicros(unix_micros),
                          absl::LocalTimeZone());
}
}  // namespace

void StatsLogger::ReportCurrFieldSample(std::vector<uint64_t> &&values) {
  if (!curr_experiment_name_.empty()) os_ << curr_experiment_name_ << ": ";

  // Print the requested aggregate stats as well as the full sorted contents of
  // `values`.
  std::sort(values.begin(), values.end());
  const uint64_t min = values.front();
  const uint64_t max = values.back();
  const uint64_t sum = std::accumulate(values.begin(), values.end(), 0.);
  const double avg = !values.empty() ? (1.0 * sum / values.size()) : 0;

  os_ << std::fixed << std::setprecision(1);
  if (curr_field_info_.traits & TraitBits::kTimestamp) {
    os_ << "min:\t" << FormatTimestamp(min) << "\t"
        << "max:\t" << FormatTimestamp(max);
  } else {
    if (curr_field_info_.traits & TraitBits::kMin)
      os_ << "min:\t" << min << "\t";
    if (curr_field_info_.traits & TraitBits::kMax)
      os_ << "max:\t" << max << "\t";
    if (curr_field_info_.traits & TraitBits::kAvg)
      os_ << "avg:\t" << avg << "\t";

    os_ << "--";
    for (auto value : values) {
      os_ << "\t" << value;
    }
  }
  os_ << "\n";
}

void StatsLogger::ReportFlags(const GroupToFlags &group_to_flags) {
  std::stringstream fos;
  for (const auto &[group_name, group_flags] : group_to_flags) {
    if (!group_name.empty() || !group_flags.empty()) {
      fos << group_name << ": " << group_flags << "\n";
    }
  }
  if (fos.tellp() != std::streampos{0}) os_ << "Flags:\n" << fos.rdbuf();
}

void StatsLogger::DoneFieldSamplesBatch() {
  LOG(INFO) << "Current stats:\n" << absl::StripAsciiWhitespace(os_.str());
  // Reset the stream for the next round of logging.
  os_.str("");
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
    if (field.traits & TraitBits::kMin)
      absl::StrAppend(&csv_header_, field.name, "_Min,");
    if (field.traits & TraitBits::kMax)
      absl::StrAppend(&csv_header_, field.name, "_Max,");
    if (field.traits & TraitBits::kAvg)
      absl::StrAppend(&csv_header_, field.name, "_Avg,");
  }
  absl::StrAppend(&csv_header_, "\n");
}

void StatsCsvFileAppender::SetCurrGroup(const Environment &master_env) {
  RemoteFile *&file = files_[master_env.experiment_name];
  if (file == nullptr) {
    const std::string filename =
        WorkDir{master_env}.FuzzingStatsPath(master_env.experiment_name);
    // TODO(ussuri): Append, not overwrite, so restarts keep accumulating.
    //  This will require writing the CSV header only if the file is brand new.
    file = RemoteFileOpen(filename, "w");
    CHECK(file != nullptr) << VV(filename);
    RemoteFileAppend(file, csv_header_);
  }
  curr_file_ = file;
}

void StatsCsvFileAppender::SetCurrField(const Stats::FieldInfo &field_info) {
  curr_field_info_ = field_info;
}

void StatsCsvFileAppender::ReportCurrFieldSample(
    std::vector<uint64_t> &&values) {
  uint64_t min = std::numeric_limits<uint64_t>::max();
  uint64_t max = std::numeric_limits<uint64_t>::min();
  uint64_t sum = 0;
  for (const auto value : values) {
    min = std::min(min, value);
    max = std::max(max, value);
    sum += value;
  }
  double avg = !values.empty() ? (1.0 * sum / values.size()) : 0;

  std::string values_str;
  if (curr_field_info_.traits & TraitBits::kMin)
    absl::StrAppendFormat(&values_str, "%" PRIu64 ",", min);
  if (curr_field_info_.traits & TraitBits::kMax)
    absl::StrAppendFormat(&values_str, "%" PRIu64 ",", max);
  if (curr_field_info_.traits & TraitBits::kAvg)
    absl::StrAppendFormat(&values_str, "%.1lf,", avg);

  RemoteFileAppend(curr_file_, values_str);
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
