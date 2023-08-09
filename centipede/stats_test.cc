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
#include "absl/time/civil_time.h"
#include "absl/time/time.h"
#include "./centipede/environment.h"
#include "./centipede/test_util.h"
#include "./centipede/util.h"

namespace centipede {

namespace {

class LogCapture : public absl::LogSink {
 public:
  LogCapture() { absl::AddLogSink(this); }
  ~LogCapture() override { absl::RemoveLogSink(this); }
  void Send(const absl::LogEntry &entry) override {
    captured_log_ << entry.text_message() << "\n";
  }
  std::string CapturedLog() const { return captured_log_.str(); }

 private:
  std::stringstream captured_log_;
};

uint64_t CivilTimeToUnixMicros(  //
    int64_t y, int64_t m, int64_t d, int64_t hh, int64_t mm, int64_t ss) {
  return absl::ToUnixMicros(absl::FromCivil(
      absl::CivilSecond{y, m, d, hh, mm, ss}, absl::LocalTimeZone()));
}

}  // namespace

TEST(Stats, PrintStatsToLog) {
  std::vector<Stats> stats_vec(4);
  stats_vec[0].num_covered_pcs = 10;
  stats_vec[1].num_covered_pcs = 15;
  stats_vec[2].num_covered_pcs = 25;
  stats_vec[3].num_covered_pcs = 40;

  stats_vec[0].corpus_size = 1000;
  stats_vec[1].corpus_size = 2000;
  stats_vec[2].corpus_size = 3000;
  stats_vec[3].corpus_size = 4000;

  for (size_t i = 0; i < 4; ++i) {
    auto &stats = stats_vec[i];
    stats.unix_micros = CivilTimeToUnixMicros(1970, 1, 1, 0, 0, i);
    stats.max_corpus_element_size = 2 * i + 1;
    stats.avg_corpus_element_size = i + 1;
    stats.num_executions = i + 100;
  }

  std::vector<Environment> env_vec(4);
  env_vec[0].experiment_name = "Experiment A";
  env_vec[0].experiment_flags = "AAA";
  env_vec[1].experiment_name = "Experiment B";
  env_vec[1].experiment_flags = "BBB";
  env_vec[2].experiment_name = "Experiment A";
  env_vec[2].experiment_flags = "AAA";
  env_vec[3].experiment_name = "Experiment B";
  env_vec[3].experiment_flags = "BBB";

  StatsLogger stats_logger{stats_vec, env_vec};

  {
    constexpr std::string_view kExpectedLogLines =
        "Current stats:\n"
        "Coverage:\n"
        "Experiment A: min:\t10\tmax:\t25\tavg:\t17.5\t--\t10\t25\n"
        "Experiment B: min:\t15\tmax:\t40\tavg:\t27.5\t--\t15\t40\n"
        "Number of executions:\n"
        "Experiment A: min:\t100\tmax:\t102\tavg:\t101.0\t--\t100\t102\n"
        "Experiment B: min:\t101\tmax:\t103\tavg:\t102.0\t--\t101\t103\n"
        "Corpus size:\n"
        "Experiment A: min:\t1000\tmax:\t3000\tavg:\t2000.0\t--\t1000\t3000\n"
        "Experiment B: min:\t2000\tmax:\t4000\tavg:\t3000.0\t--\t2000\t4000\n"
        "Max element size:\n"
        "Experiment A: min:\t1\tmax:\t5\tavg:\t3.0\t--\t1\t5\n"
        "Experiment B: min:\t3\tmax:\t7\tavg:\t5.0\t--\t3\t7\n"
        "Avg element size:\n"
        "Experiment A: min:\t1\tmax:\t3\tavg:\t2.0\t--\t1\t3\n"
        "Experiment B: min:\t2\tmax:\t4\tavg:\t3.0\t--\t2\t4\n"
        "Timestamp:\n"
        "Experiment A: min:\t1970-01-01T00:00:00\tmax:\t1970-01-01T00:00:02\n"
        "Experiment B: min:\t1970-01-01T00:00:01\tmax:\t1970-01-01T00:00:03\n"
        "Flags:\n"
        "Experiment A: AAA\n"
        "Experiment B: BBB\n";
    LogCapture log_capture;
    stats_logger.ReportCurrStats();
    EXPECT_THAT(log_capture.CapturedLog(), testing::StrEq(kExpectedLogLines));
  }

  {
    for (auto &stats : stats_vec) {
      stats.num_covered_pcs += 100;
      stats.num_executions += 1000;
      stats.corpus_size += 1;
      stats.max_corpus_element_size += 10;
      stats.avg_corpus_element_size += 10;
      stats.unix_micros += 1000000;
    }

    constexpr std::string_view kExpectedLogLines =
        "Current stats:\n"
        "Coverage:\n"
        "Experiment A: min:\t110\tmax:\t125\tavg:\t117.5\t--\t110\t125\n"
        "Experiment B: min:\t115\tmax:\t140\tavg:\t127.5\t--\t115\t140\n"
        "Number of executions:\n"
        "Experiment A: min:\t1100\tmax:\t1102\tavg:\t1101.0\t--\t1100\t1102\n"
        "Experiment B: min:\t1101\tmax:\t1103\tavg:\t1102.0\t--\t1101\t1103\n"
        "Corpus size:\n"
        "Experiment A: min:\t1001\tmax:\t3001\tavg:\t2001.0\t--\t1001\t3001\n"
        "Experiment B: min:\t2001\tmax:\t4001\tavg:\t3001.0\t--\t2001\t4001\n"
        "Max element size:\n"
        "Experiment A: min:\t11\tmax:\t15\tavg:\t13.0\t--\t11\t15\n"
        "Experiment B: min:\t13\tmax:\t17\tavg:\t15.0\t--\t13\t17\n"
        "Avg element size:\n"
        "Experiment A: min:\t11\tmax:\t13\tavg:\t12.0\t--\t11\t13\n"
        "Experiment B: min:\t12\tmax:\t14\tavg:\t13.0\t--\t12\t14\n"
        "Timestamp:\n"
        "Experiment A: min:\t1970-01-01T00:00:01\tmax:\t1970-01-01T00:00:03\n"
        "Experiment B: min:\t1970-01-01T00:00:02\tmax:\t1970-01-01T00:00:04\n"
        "Flags:\n"
        "Experiment A: AAA\n"
        "Experiment B: BBB\n";
    LogCapture log_capture;
    stats_logger.ReportCurrStats();
    EXPECT_THAT(log_capture.CapturedLog(), testing::StrEq(kExpectedLogLines));
  }
}

TEST(Stats, DumpStatsToCsvFile) {
  const std::filesystem::path workdir = GetTestTempDir(test_info_->name());

  std::vector<Stats> stats_vec(4);
  stats_vec[0].num_covered_pcs = 10;
  stats_vec[0].corpus_size = 1000;
  stats_vec[1].num_covered_pcs = 15;
  stats_vec[1].corpus_size = 2000;
  stats_vec[2].num_covered_pcs = 25;
  stats_vec[2].corpus_size = 3000;
  stats_vec[3].num_covered_pcs = 40;
  stats_vec[3].corpus_size = 4000;
  for (size_t i = 0; i < 4; ++i) {
    auto &stats = stats_vec[i];
    stats.unix_micros = i + 1000000;
    stats.max_corpus_element_size = 2 * i + 1;
    stats.avg_corpus_element_size = i + 1;
    stats.num_executions = i + 100;
  }

  std::vector<Environment> env_vec(4);
  env_vec[0].experiment_name = "ExperimentA";
  env_vec[0].experiment_flags = "AAA";
  env_vec[1].experiment_name = "ExperimentB";
  env_vec[1].experiment_flags = "BBB";
  env_vec[2].experiment_name = "ExperimentA";
  env_vec[2].experiment_flags = "AAA";
  env_vec[3].experiment_name = "ExperimentB";
  env_vec[3].experiment_flags = "BBB";
  for (auto &env : env_vec) {
    env.workdir = workdir;
  }

  {
    StatsCsvFileAppender stats_csv_appender{stats_vec, env_vec};
    stats_csv_appender.ReportCurrStats();

    for (auto &stats : stats_vec) {
      stats.unix_micros += 1;
      stats.num_executions += 1;
      stats.num_covered_pcs += 1;
      stats.corpus_size += 1;
      stats.max_corpus_element_size += 1;
      stats.avg_corpus_element_size += 1;
    }

    stats_csv_appender.ReportCurrStats();
  }

  const std::vector<std::string> kExpectedCsvs = {
      workdir / "fuzzing-stats-.000000.ExperimentA.csv",
      workdir / "fuzzing-stats-.000000.ExperimentB.csv",
  };
  const std::vector<std::string_view> kExpectedCsvContents = {
      R"(NumCoveredPcs_Min,NumCoveredPcs_Max,NumCoveredPcs_Avg,NumExecs_Min,NumExecs_Max,NumExecs_Avg,CorpusSize_Min,CorpusSize_Max,CorpusSize_Avg,MaxEltSize_Min,MaxEltSize_Max,MaxEltSize_Avg,AvgEltSize_Min,AvgEltSize_Max,AvgEltSize_Avg,UnixMicros_Min,UnixMicros_Max,
10,25,17.5,100,102,101.0,1000,3000,2000.0,1,5,3.0,1,3,2.0,1000000,1000002,
11,26,18.5,101,103,102.0,1001,3001,2001.0,2,6,4.0,2,4,3.0,1000001,1000003,
)",
      R"(NumCoveredPcs_Min,NumCoveredPcs_Max,NumCoveredPcs_Avg,NumExecs_Min,NumExecs_Max,NumExecs_Avg,CorpusSize_Min,CorpusSize_Max,CorpusSize_Avg,MaxEltSize_Min,MaxEltSize_Max,MaxEltSize_Avg,AvgEltSize_Min,AvgEltSize_Max,AvgEltSize_Avg,UnixMicros_Min,UnixMicros_Max,
15,40,27.5,101,103,102.0,2000,4000,3000.0,3,7,5.0,2,4,3.0,1000001,1000003,
16,41,28.5,102,104,103.0,2001,4001,3001.0,4,8,6.0,3,5,4.0,1000002,1000004,
)",
  };

  for (int i = 0; i < 2; ++i) {
    ASSERT_TRUE(std::filesystem::exists(kExpectedCsvs[i]));
    std::string csv_contents;
    ReadFromLocalFile(kExpectedCsvs[i], csv_contents);
    EXPECT_EQ(csv_contents, kExpectedCsvContents[i]);
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
  LOG(INFO) << "\n" << ss.str();
  const char *expected =
      "REWARD_MAX 40\n"
      "REWARD_SECOND_MAX 25\n"
      "REWARD_MIN 10\n"
      "REWARD_MEDIAN 25\n"
      "REWARD_AVERAGE 22.5\n";
  EXPECT_THAT(ss.str(), testing::StrEq(expected));
}

}  // namespace centipede
