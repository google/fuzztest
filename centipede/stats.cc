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
#include <map>
#include <numeric>
#include <string>

#include "absl/container/flat_hash_set.h"
#include "absl/types/span.h"
#include "./centipede/environment.h"
#include "./centipede/logging.h"

namespace centipede {

namespace {
// Helper for PrintExperimentStats().
// Prints the experiment summary for the `field`.
void PrintExperimentStatsForOneStatValue(absl::Span<const Stats> stats_vec,
                                         absl::Span<const Environment> env_vec,
                                         std::ostream &os,
                                         std::atomic<uint64_t> Stats::*field) {
  CHECK_EQ(stats_vec.size(), env_vec.size());
  // Maps experiment names to indices in env_vec/stats_vec.
  // We use std::map because we want lexicographic order of experiment names.
  std::map<std::string_view, std::vector<size_t>> experiment_to_indices;
  for (size_t i = 0; i < env_vec.size(); ++i) {
    experiment_to_indices[env_vec[i].experiment_name].push_back(i);
  }

  // Iterate over every experiment_name.
  for (const auto &[experiment_name, experiment_indices] :
       experiment_to_indices) {
    os << experiment_name << ": ";
    std::vector<uint64_t> stat_values;
    CHECK_NE(experiment_indices.size(), 0);
    // Get the required stat fields into a vector `stat_values`.
    stat_values.reserve(experiment_indices.size());
    for (const auto idx : experiment_indices) {
      // stat_values.push_back(extract_value(stats_vec[idx]));
      stat_values.push_back((stats_vec[idx].*field));
    }
    // Print min/max/avg and the full sorted contents of `stat_values`.
    std::sort(stat_values.begin(), stat_values.end());
    os << "min:\t" << stat_values.front() << "\t";
    os << "max:\t" << stat_values.back() << "\t";
    os << "avg:\t"
       << (std::accumulate(stat_values.begin(), stat_values.end(), 0.) /
           static_cast<double>(stat_values.size()))
       << "\t";
    os << "--";
    for (const auto value : stat_values) {
      os << "\t" << value;
    }
    os << std::endl;
  }
}

}  // namespace

void PrintExperimentStats(absl::Span<const Stats> stats_vec,
                          absl::Span<const Environment> env_vec,
                          std::ostream &os) {
  os << "Coverage:\n";
  PrintExperimentStatsForOneStatValue(stats_vec, env_vec, os,
                                      &Stats::num_covered_pcs);

  os << "Corpus size:\n";
  PrintExperimentStatsForOneStatValue(stats_vec, env_vec, os,
                                      &Stats::corpus_size);
  os << "Max corpus element size:\n";
  PrintExperimentStatsForOneStatValue(stats_vec, env_vec, os,
                                      &Stats::max_corpus_element_size);

  os << "Avg corpus element size:\n";
  PrintExperimentStatsForOneStatValue(stats_vec, env_vec, os,
                                      &Stats::avg_corpus_element_size);
  os << "Number of executions:\n";
  PrintExperimentStatsForOneStatValue(stats_vec, env_vec, os,
                                      &Stats::num_executions);

  os << "Flags:\n";
  absl::flat_hash_set<std::string> printed_names;
  for (const auto &env : env_vec) {
    if (!printed_names.insert(env.experiment_name).second) continue;
    os << env.experiment_name << ": " << env.experiment_flags << "\n";
  }
}

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
