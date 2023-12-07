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
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <initializer_list>
#include <iomanip>
#include <ios>
#include <iosfwd>
#include <limits>
#include <memory>
#include <numeric>
#include <sstream>
#include <string>
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
#include "riegeli/bytes/writer.h"
#include "riegeli/csv/csv_writer.h"

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
  curr_field_info_ = field_info;
}

namespace {
std::string FormatTimestamp(uint64_t unix_micros) {
  return absl::FormatTime("%Y-%m-%d%ET%H:%M:%S",
                          absl::FromUnixMicros(unix_micros),
                          absl::LocalTimeZone());
}
}  // namespace

void StatsLogger::ReportCurrFieldSample(std::vector<uint64_t> &&values) {
  // Print min/max/avg and the full sorted contents of `values`.
  std::sort(values.begin(), values.end());
  const uint64_t min = values.front();
  const uint64_t max = values.back();
  const double avg = std::accumulate(values.begin(), values.end(), 0.) /
                     static_cast<double>(values.size());
  os_ << std::fixed << std::setprecision(1);
  switch (curr_field_info_.aggregation) {
    case Stats::Aggregation::kMinMaxAvg: {
      os_ << "min:\t" << min << "\t"
          << "max:\t" << max << "\t"
          << "avg:\t" << avg << "\t";
      os_ << "--";
      for (const auto value : values) {
        os_ << "\t" << value;
      }
    } break;
    case Stats::Aggregation::kMinMax: {
      os_ << "min:\t" << FormatTimestamp(min) << "\t"
          << "max:\t" << FormatTimestamp(max);
    } break;
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
  for (const auto &[group_name, csv_writer_with_record] : csv_writers_) {
    CHECK(csv_writer_with_record.csv_writer->Close())
        << VV(csv_writer_with_record.csv_writer->status());
  }
}

void StatsCsvFileAppender::PreAnnounceFields(
    std::initializer_list<Stats::FieldInfo> fields) {
  if (!csv_header_.empty()) return;

  for (const auto &field : fields) {
    switch (field.aggregation) {
      case Stats::Aggregation::kMinMax:
        csv_header_.Add(absl::StrCat(field.name, "_Min"),
                        absl::StrCat(field.name, "_Max"));
        break;
      case Stats::Aggregation::kMinMaxAvg:
        csv_header_.Add(absl::StrCat(field.name, "_Min"),
                        absl::StrCat(field.name, "_Max"),
                        absl::StrCat(field.name, "_Avg"));
        break;
    }
  }
}

void StatsCsvFileAppender::SetCurrGroup(const Environment &master_env) {
  curr_csv_writer_ = &csv_writers_[master_env.experiment_name];
  if (curr_csv_writer_->csv_writer == nullptr) {
    const std::string filename =
        WorkDir{master_env}.FuzzingStatsPath(master_env.experiment_name);
    auto writer = CreateRiegeliFileWriter(filename, /*append=*/true);
    CHECK(writer->ok()) << VV(writer->status());
    riegeli::CsvWriterBase::Options options;
    if (writer->pos() == 0) options.set_header(csv_header_);
    curr_csv_writer_->csv_writer =
        std::make_unique<riegeli::CsvWriter<std::unique_ptr<riegeli::Writer>>>(
            std::move(writer), std::move(options));
    curr_csv_writer_->record.reserve(csv_header_.size());
  }
}

void StatsCsvFileAppender::SetCurrField(const Stats::FieldInfo &field_info) {
  curr_field_info_ = field_info;
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
  switch (curr_field_info_.aggregation) {
    case Stats::Aggregation::kMinMax:
      curr_csv_writer_->record.push_back(absl::StrCat(min));
      curr_csv_writer_->record.push_back(absl::StrCat(max));
      break;
    case Stats::Aggregation::kMinMaxAvg:
      curr_csv_writer_->record.push_back(absl::StrCat(min));
      curr_csv_writer_->record.push_back(absl::StrCat(max));
      curr_csv_writer_->record.push_back(absl::StrFormat("%.1f", avg));
      break;
  }
}

void StatsCsvFileAppender::ReportFlags(const GroupToFlags &group_to_flags) {
  // Do nothing: can't write to CSV, as it has no concept of comments.
  // TODO(ussuri): Consider writing to a sidecar file.
}

void StatsCsvFileAppender::DoneFieldSamplesBatch() {
  for (auto &[group_name, csv_writer_with_record] : csv_writers_) {
    csv_writer_with_record.csv_writer->WriteRecord(
        csv_writer_with_record.record);
    csv_writer_with_record.record.clear();
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
