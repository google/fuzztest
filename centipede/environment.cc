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

#include "./centipede/environment.h"

#include <algorithm>
#include <bitset>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <string>
#include <system_error>  // NOLINT
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "./centipede/defs.h"
#include "./centipede/feature.h"
#include "./centipede/knobs.h"
#include "./centipede/logging.h"
#include "./centipede/remote_file.h"

namespace centipede {

bool Environment::DumpCorpusTelemetryInThisShard() const {
  // Corpus stats are global across all shards on all machines.
  return my_shard_index == 0 && telemetry_frequency != 0;
}

bool Environment::DumpRUsageTelemetryInThisShard() const {
  // Unlike the corpus stats, we want to measure/dump rusage stats for each
  // Centipede process running on a separate machine: assign that to the first
  // shard (i.e. thread) on the machine.
  return my_shard_index % num_threads == 0;
}

bool Environment::DumpTelemetryForThisBatch(size_t batch_index) const {
  // Always dump for batch 0 (i.e. at the beginning of execution).
  if (telemetry_frequency != 0 && batch_index == 0) {
    return true;
  }
  // Special mode for negative --telemetry_frequency: dump when batch_index
  // is a power-of-two and is >= than 2^abs(--telemetry_frequency).
  if (telemetry_frequency < 0 && batch_index >= (1 << -telemetry_frequency) &&
      ((batch_index - 1) & batch_index) == 0) {
    return true;
  }
  // Normal mode: dump when requested number of batches get processed.
  if (((telemetry_frequency > 0) && (batch_index % telemetry_frequency == 0))) {
    return true;
  }
  return false;
}

std::bitset<feature_domains::kNumDomains> Environment::MakeDomainDiscardMask()
    const {
  constexpr size_t kNumUserDomains = std::size(feature_domains::kUserDomains);
  std::bitset<kNumUserDomains> user_feature_domain_enabled(
      user_feature_domain_mask);
  std::bitset<feature_domains::kNumDomains> discard;
  for (size_t i = 0; i < kNumUserDomains; ++i) {
    if (!user_feature_domain_enabled.test(i)) {
      discard.set(feature_domains::kUserDomains[i].domain_id());
    }
  }
  return discard;
}

// Returns true if `value` is one of "1", "true".
// Returns true if `value` is one of "0", "false".
// CHECK-fails otherwise.
static bool GetBoolFlag(std::string_view value) {
  if (value == "0" || value == "false") return false;
  CHECK(value == "1" || value == "true") << value;
  return true;
}

// Returns `value` as a size_t, CHECK-fails on parse error.
static size_t GetIntFlag(std::string_view value) {
  size_t result{};
  CHECK(std::from_chars(value.data(), value.data() + value.size(), result).ec ==
        std::errc())
      << value;
  return result;
}

void Environment::SetFlagForExperiment(std::string_view name,
                                       std::string_view value) {
  // TODO(kcc): support more flags, as needed.

  // Handle bool flags.
  absl::flat_hash_map<std::string, bool *> bool_flags{
      {"use_cmp_features", &use_cmp_features},
      {"use_auto_dictionary", &use_auto_dictionary},
      {"use_dataflow_features", &use_dataflow_features},
      {"use_counter_features", &use_counter_features},
      {"use_pcpair_features", &use_pcpair_features},
      {"use_coverage_frontier", &use_coverage_frontier},
      {"use_legacy_default_mutator", &use_legacy_default_mutator},
  };
  auto bool_iter = bool_flags.find(name);
  if (bool_iter != bool_flags.end()) {
    *bool_iter->second = GetBoolFlag(value);
    return;
  }

  // Handle int flags.
  absl::flat_hash_map<std::string, size_t *> int_flags{
      {"path_level", &path_level},
      {"callstack_level", &callstack_level},
      {"max_corpus_size", &max_corpus_size},
      {"max_len", &max_len},
      {"crossover_level", &crossover_level},
      {"mutate_batch_size", &mutate_batch_size},
      {"feature_frequency_threshold", &feature_frequency_threshold},
  };
  auto int_iter = int_flags.find(name);
  if (int_iter != int_flags.end()) {
    *int_iter->second = GetIntFlag(value);
    return;
  }

  LOG(FATAL) << "Unknown flag for experiment: " << name << "=" << value;
}

void Environment::UpdateForExperiment() {
  if (experiment.empty()) return;

  // Parse the --experiments flag.
  struct Experiment {
    std::string flag_name;
    std::vector<std::string> flag_values;
  };
  std::vector<Experiment> experiments;
  for (auto flag : absl::StrSplit(this->experiment, ':', absl::SkipEmpty())) {
    std::vector<std::string> flag_and_value = absl::StrSplit(flag, '=');
    CHECK_EQ(flag_and_value.size(), 2) << flag;
    experiments.emplace_back(
        Experiment{flag_and_value[0], absl::StrSplit(flag_and_value[1], ',')});
  }

  // Count the number of flag combinations.
  size_t num_combinations = 1;
  for (const auto &exp : experiments) {
    CHECK_NE(exp.flag_values.size(), 0) << exp.flag_name;
    num_combinations *= exp.flag_values.size();
  }
  CHECK_GT(num_combinations, 0);
  CHECK_EQ(num_threads % num_combinations, 0)
      << VV(num_threads) << VV(num_combinations);

  // Update the flags for the current shard and compute experiment_name.
  CHECK_LT(my_shard_index, num_threads);
  size_t my_combination_num = my_shard_index % num_combinations;
  experiment_name.clear();
  experiment_flags.clear();
  // Reverse the flags.
  // This way, the flag combinations will go in natural order.
  // E.g. for --experiment='foo=1,2,3:bar=10,20' the order of combinations is
  //   foo=1 bar=10
  //   foo=1 bar=20
  //   foo=2 bar=10 ...
  // Alternative would be to iterate in reverse order with rbegin()/rend().
  std::reverse(experiments.begin(), experiments.end());
  for (const auto &exp : experiments) {
    size_t idx = my_combination_num % exp.flag_values.size();
    SetFlagForExperiment(exp.flag_name, exp.flag_values[idx]);
    my_combination_num /= exp.flag_values.size();
    experiment_name = std::to_string(idx) + experiment_name;
    experiment_flags =
        exp.flag_name + "=" + exp.flag_values[idx] + ":" + experiment_flags;
  }
  experiment_name = "E" + experiment_name;
  load_other_shard_frequency = 0;  // The experiments should be independent.
}

void Environment::ReadKnobsFileIfSpecified() {
  const std::string_view knobs_file_path = knobs_file;
  if (knobs_file_path.empty()) return;
  ByteArray knob_bytes;
  auto *f = RemoteFileOpen(knobs_file, "r");
  CHECK(f) << "Failed to open remote file " << knobs_file;
  RemoteFileRead(f, knob_bytes);
  RemoteFileClose(f);
  VLOG(1) << "Knobs: " << knob_bytes.size() << " knobs read from "
          << knobs_file;
  knobs.Set(knob_bytes);
  knobs.ForEachKnob([](std::string_view name, Knobs::value_type value) {
    VLOG(1) << "knob " << name << ": " << static_cast<uint32_t>(value);
  });
}

}  // namespace centipede
