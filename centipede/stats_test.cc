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

#include <cstddef>
#include <cstdint>
#include <filesystem>  // NOLINT
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/log_entry.h"
#include "absl/log/log_sink.h"
#include "absl/log/log_sink_registry.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "absl/time/civil_time.h"
#include "absl/time/time.h"
#include "./centipede/environment.h"
#include "./centipede/logging.h"  // IWYU pragma: keep
#include "./centipede/test_util.h"
#include "./centipede/util.h"

namespace centipede {

using ::testing::ElementsAreArray;

namespace {

class LogCapture : public absl::LogSink {
 public:
  LogCapture() { absl::AddLogSink(this); }
  ~LogCapture() override { absl::RemoveLogSink(this); }
  void Send(const absl::LogEntry &entry) override {
    captured_log_.emplace_back(entry.text_message());
  }
  std::vector<std::string> CapturedLogLines() const {
    // Join->Split normalizes multi-line messages.
    return absl::StrSplit(absl::StrJoin(captured_log_, "\n"), '\n');
  }

 private:
  std::vector<std::string> captured_log_;
};

uint64_t CivilTimeToUnixMicros(  //
    int64_t y, int64_t m, int64_t d, int64_t hh, int64_t mm, int64_t ss) {
  return absl::ToUnixMicros(absl::FromCivil(
      absl::CivilSecond{y, m, d, hh, mm, ss}, absl::LocalTimeZone()));
}

}  // namespace

TEST(Stats, PrintStatsToLog) {
  std::vector<Stats> stats_vec(4);
  for (int i = 0; i < stats_vec.size(); ++i) {
    const auto j = i + 1;
    auto &stats = stats_vec[i];
    // NOTE: Use placement-new because `Stats` is not copyable nor moveable but
    // we want designated initializers, for convenience and to compile-enforce
    // the order as in the declaration. This is safe, because `~Stats` is
    // trivial.
    new (&stats) Stats{
        .timestamp_unix_micros = CivilTimeToUnixMicros(1970, 1, 1, 0, 0, i),
        .num_executions = 12 * j,
        .num_covered_pcs = 21 * j,
        .active_corpus_size = 101 * j,
        .max_corpus_element_size = 103 * j,
        .avg_corpus_element_size = 104 * j,
    };
  }

  const std::vector<Environment> env_vec = {
      {.experiment_name = "Experiment A", .experiment_flags = "AAA"},
      {.experiment_name = "Experiment B", .experiment_flags = "BBB"},
      {.experiment_name = "Experiment A", .experiment_flags = "AAA"},
      {.experiment_name = "Experiment B", .experiment_flags = "BBB"},
  };

  StatsLogger stats_logger{stats_vec, env_vec};

  {
    const std::vector<std::string_view> kExpectedLogLines = {
        "Current stats:",
        "Coverage:",
        "  Experiment A: min:\t21\tmax:\t63\tavg:\t42.0\t--\t21\t63",
        "  Experiment B: min:\t42\tmax:\t84\tavg:\t63.0\t--\t42\t84",
        "Number of executions:",
        "  Experiment A: min:\t12\tmax:\t36\tavg:\t24.0\t--\t12\t36",
        "  Experiment B: min:\t24\tmax:\t48\tavg:\t36.0\t--\t24\t48",
        "Active corpus size:",
        "  Experiment A: min:\t101\tmax:\t303\tavg:\t202.0\t--\t101\t303",
        "  Experiment B: min:\t202\tmax:\t404\tavg:\t303.0\t--\t202\t404",
        "Max element size:",
        "  Experiment A: min:\t103\tmax:\t309\tavg:\t206.0\t--\t103\t309",
        "  Experiment B: min:\t206\tmax:\t412\tavg:\t309.0\t--\t206\t412",
        "Avg element size:",
        "  Experiment A: min:\t104\tmax:\t312\tavg:\t208.0\t--\t104\t312",
        "  Experiment B: min:\t208\tmax:\t416\tavg:\t312.0\t--\t208\t416",
        "Flags:",
        "  Experiment A: AAA",
        "  Experiment B: BBB",
    };

    LogCapture log_capture;
    stats_logger.ReportCurrStats();

    const auto log_lines = log_capture.CapturedLogLines();
    EXPECT_THAT(log_lines, ElementsAreArray(kExpectedLogLines));
  }

  {
    for (auto &stats : stats_vec) {
      stats.timestamp_unix_micros += 1000000;
      stats.num_executions += 1;
      stats.num_covered_pcs += 1;
      stats.active_corpus_size += 1;
      stats.max_corpus_element_size += 1;
      stats.avg_corpus_element_size += 1;
    }

    const std::vector<std::string_view> kExpectedLogLines = {
        "Current stats:",
        "Coverage:",
        "  Experiment A: min:\t22\tmax:\t64\tavg:\t43.0\t--\t22\t64",
        "  Experiment B: min:\t43\tmax:\t85\tavg:\t64.0\t--\t43\t85",
        "Number of executions:",
        "  Experiment A: min:\t13\tmax:\t37\tavg:\t25.0\t--\t13\t37",
        "  Experiment B: min:\t25\tmax:\t49\tavg:\t37.0\t--\t25\t49",
        "Active corpus size:",
        "  Experiment A: min:\t102\tmax:\t304\tavg:\t203.0\t--\t102\t304",
        "  Experiment B: min:\t203\tmax:\t405\tavg:\t304.0\t--\t203\t405",
        "Max element size:",
        "  Experiment A: min:\t104\tmax:\t310\tavg:\t207.0\t--\t104\t310",
        "  Experiment B: min:\t207\tmax:\t413\tavg:\t310.0\t--\t207\t413",
        "Avg element size:",
        "  Experiment A: min:\t105\tmax:\t313\tavg:\t209.0\t--\t105\t313",
        "  Experiment B: min:\t209\tmax:\t417\tavg:\t313.0\t--\t209\t417",
        "Flags:",
        "  Experiment A: AAA",
        "  Experiment B: BBB",
    };

    LogCapture log_capture;
    stats_logger.ReportCurrStats();

    const auto log_lines = log_capture.CapturedLogLines();
    EXPECT_THAT(log_lines, ElementsAreArray(kExpectedLogLines));
  }
}

TEST(Stats, DumpStatsToCsvFile) {
  const std::filesystem::path workdir = GetTestTempDir(test_info_->name());

  std::vector<Stats> stats_vec(4);
  for (int i = 0; i < stats_vec.size(); ++i) {
    const auto j = i + 1;
    auto &stats = stats_vec[i];
    // NOTE: Use placement-new because `Stats` is not copyable nor moveable but
    // we want designated initializers, for convenience and to compile-enforce
    // the order as in the declaration. This is safe, because `~Stats` is
    // trivial.
    new (&stats) Stats{
        .timestamp_unix_micros = 1000000 * j,
        .num_executions = 12 * j,
        .num_covered_pcs = 21 * j,
        .active_corpus_size = 101 * j,
        .max_corpus_element_size = 103 * j,
        .avg_corpus_element_size = 104 * j,
    };
  }

  const std::vector<Environment> env_vec = {
      {
          .workdir = workdir,
          .experiment_name = "ExperimentA",
          .experiment_flags = "AAA",
      },
      {
          .workdir = workdir,
          .experiment_name = "ExperimentB",
          .experiment_flags = "BBB",
      },
      {
          .workdir = workdir,
          .experiment_name = "ExperimentA",
          .experiment_flags = "AAA",
      },
      {
          .workdir = workdir,
          .experiment_name = "ExperimentB",
          .experiment_flags = "BBB",
      },
  };

  {
    StatsCsvFileAppender stats_csv_appender{stats_vec, env_vec};
    stats_csv_appender.ReportCurrStats();

    // Emulate progress in shard #2 of each experiment. In the second line of
    // each CSV, min's shouldn't change, max's should increase by 1, avg's
    // should increase by 0.5.
    for (int i = 2; i < stats_vec.size(); ++i) {
      auto &stats = stats_vec[i];
      stats.timestamp_unix_micros += 1;
      stats.num_executions += 1;
      stats.num_covered_pcs += 1;
      stats.active_corpus_size += 1;
      stats.max_corpus_element_size += 1;
      stats.avg_corpus_element_size += 1;
    }

    stats_csv_appender.ReportCurrStats();
  }

  const std::vector<std::string> kExpectedCsvs = {
      workdir / "fuzzing-stats-.000000.ExperimentA.csv",
      workdir / "fuzzing-stats-.000000.ExperimentB.csv",
  };
  const std::vector<std::vector<std::string>> kExpectedCsvLines = {
      // CSV #1.
      {
          // Header.
          "NumCoveredPcs_Min,NumCoveredPcs_Max,NumCoveredPcs_Avg,"
          "NumExecs_Min,NumExecs_Max,NumExecs_Avg,"
          "ActiveCorpusSize_Min,ActiveCorpusSize_Max,ActiveCorpusSize_Avg,"
          "MaxEltSize_Min,MaxEltSize_Max,MaxEltSize_Avg,"
          "AvgEltSize_Min,AvgEltSize_Max,AvgEltSize_Avg,"
          "UnixMicros_Min,UnixMicros_Max,",
          // Line 1.
          "21,63,42.0,"
          "12,36,24.0,"
          "101,303,202.0,"
          "103,309,206.0,"
          "104,312,208.0,"
          "1000000,3000000,",
          // Line 2.
          "21,64,42.5,"
          "12,37,24.5,"
          "101,304,202.5,"
          "103,310,206.5,"
          "104,313,208.5,"
          "1000000,3000001,",
          "",  // empty line at EOF
      },
      // CSV #2.
      {
          // Header.
          "NumCoveredPcs_Min,NumCoveredPcs_Max,NumCoveredPcs_Avg,"
          "NumExecs_Min,NumExecs_Max,NumExecs_Avg,"
          "ActiveCorpusSize_Min,ActiveCorpusSize_Max,ActiveCorpusSize_Avg,"
          "MaxEltSize_Min,MaxEltSize_Max,MaxEltSize_Avg,"
          "AvgEltSize_Min,AvgEltSize_Max,AvgEltSize_Avg,"
          "UnixMicros_Min,UnixMicros_Max,",
          // Line 1.
          "42,84,63.0,"
          "24,48,36.0,"
          "202,404,303.0,"
          "206,412,309.0,"
          "208,416,312.0,"
          "2000000,4000000,",
          // Line 2.
          "42,85,63.5,"
          "24,49,36.5,"
          "202,405,303.5,"
          "206,413,309.5,"
          "208,417,312.5,"
          "2000000,4000001,",
          "",  // empty line at EOF
      }};

  for (int i = 0; i < 2; ++i) {
    ASSERT_TRUE(std::filesystem::exists(kExpectedCsvs[i]));
    std::string csv_contents;
    ReadFromLocalFile(kExpectedCsvs[i], csv_contents);

    const auto csv_lines = absl::StrSplit(csv_contents, '\n');
    EXPECT_THAT(csv_lines, ElementsAreArray(kExpectedCsvLines[i])) << VV(i);
  }
}

TEST(Stats, PrintRewardValues) {
  std::stringstream ss;
  std::vector<Stats> stats_vec(4);
  stats_vec[0].num_covered_pcs = 15;
  stats_vec[1].num_covered_pcs = 10;
  stats_vec[2].num_covered_pcs = 40;
  stats_vec[3].num_covered_pcs = 25;
  PrintRewardValues(stats_vec, ss);
  const char *expected =
      "REWARD_MAX 40\n"
      "REWARD_SECOND_MAX 25\n"
      "REWARD_MIN 10\n"
      "REWARD_MEDIAN 25\n"
      "REWARD_AVERAGE 22.5\n";
  EXPECT_EQ(ss.str(), expected);
}

}  // namespace centipede
