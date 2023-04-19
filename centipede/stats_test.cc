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

#include <sstream>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./centipede/logging.h"

namespace centipede {

TEST(Stats, PrintExperimentStats) {
  std::stringstream ss;
  std::vector<Stats> stats_vec(4);
  stats_vec[0].num_covered_pcs = 10;
  stats_vec[1].num_covered_pcs = 15;
  stats_vec[2].num_covered_pcs = 25;
  stats_vec[3].num_covered_pcs = 40;

  stats_vec[0].corpus_size = 1000;
  stats_vec[1].corpus_size = 2000;
  stats_vec[2].corpus_size = 3000;
  stats_vec[3].corpus_size = 4000;

  std::vector<Environment> env_vec(4);
  env_vec[0].experiment_name = "Experiment A";
  env_vec[0].experiment_flags = "AAA";
  env_vec[1].experiment_name = "Experiment B";
  env_vec[1].experiment_flags = "BBB";
  env_vec[2].experiment_name = "Experiment A";
  env_vec[2].experiment_flags = "AAA";
  env_vec[3].experiment_name = "Experiment B";
  env_vec[3].experiment_flags = "BBB";

  PrintExperimentStats(stats_vec, env_vec, ss);
  LOG(INFO) << "\n" << ss.str();
  const char *expected =
      "Coverage:\n"
      "Experiment A: min:\t10\tmax:\t25\tavg:\t17.5\t--\t10\t25\n"
      "Experiment B: min:\t15\tmax:\t40\tavg:\t27.5\t--\t15\t40\n"
      "Corpus size:\n"
      "Experiment A: min:\t1000\tmax:\t3000\tavg:\t2000\t--\t1000\t3000\n"
      "Experiment B: min:\t2000\tmax:\t4000\tavg:\t3000\t--\t2000\t4000\n"
      "Flags:\n"
      "Experiment A: AAA\n"
      "Experiment B: BBB\n";

  EXPECT_THAT(ss.str(), testing::StrEq(expected));
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
