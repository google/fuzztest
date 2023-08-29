// Copyright 2023 The Centipede Authors.
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

#include "./centipede/distill.h"

#include <algorithm>
#include <cstdlib>
#include <functional>
#include <numeric>
#include <string>
#include <thread>  // NOLINT(build/c++11)
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "./centipede/blob_file.h"
#include "./centipede/defs.h"
#include "./centipede/environment.h"
#include "./centipede/feature.h"
#include "./centipede/feature_set.h"
#include "./centipede/logging.h"
#include "./centipede/shard_reader.h"
#include "./centipede/util.h"

namespace centipede {

void DistillTask(const Environment &env,
                 const std::vector<size_t> &shard_indices) {
  std::string log_line = absl::StrCat("DISTILL[S.", env.my_shard_index, "]: ");
  const auto distill_to_path = env.MakeDistilledPath();
  LOG(INFO) << log_line << VV(env.total_shards) << VV(distill_to_path);

  const auto appender = DefaultBlobFileWriterFactory();
  // NOTE: Overwrite distilled corpus files -- do not append.
  CHECK_OK(appender->Open(distill_to_path, "w"));
  FeatureSet feature_set(/*frequency_threshold=*/1);
  for (size_t shard_idx : shard_indices) {
    LOG(INFO) << log_line << "reading shard " << shard_idx;
    // Read records from the current shard.
    std::vector<std::pair<ByteArray, FeatureVec>> records;
    ReadShard(env.MakeCorpusPath(shard_idx), env.MakeFeaturesPath(shard_idx),
              [&](const ByteArray &input, FeatureVec &input_features) {
                records.emplace_back(input, std::move(input_features));
              });
    // Reverse the order of inputs read from the current shard.
    // The intuition is as follows:
    // * If the shard is the result of fuzzing with Centipede, the inputs that
    //   are closer to the end are more interesting, so we start there.
    // * If the shard resulted from somethening else, the reverse order is not
    //  any better or worse than any other order.
    std::reverse(records.begin(), records.end());
    // Iterate the records, add those that have new features.
    // This is a simple linear greedy set cover algorithm.
    for (auto &&[input, features] : records) {
      VLOG(1) << log_line << VV(input.size()) << VV(features.size());
      if (!feature_set.CountUnseenAndPruneFrequentFeatures(features)) continue;
      feature_set.IncrementFrequencies(features);
      // Logging will log names of these variables.
      auto num_new_features = features.size();
      CHECK_NE(num_new_features, 0);
      auto cov = feature_set.CountFeatures(feature_domains::kPCs);
      auto ft = feature_set.size();
      LOG(INFO) << log_line << "adding to distilled: " << VV(ft) << VV(cov)
                << VV(input.size()) << VV(num_new_features);
      // Append to the distilled corpus.
      CHECK_OK(appender->Write(input));
    }
  }
}

int Distill(const Environment &env) {
  // Run `env.num_threads` independent distillation threads.
  std::vector<std::thread> threads(env.num_threads);
  std::vector<Environment> envs(env.num_threads, env);
  std::vector<std::vector<size_t>> shard_indices_per_thread(env.num_threads);
  // Start the threads.
  for (size_t thread_idx = 0; thread_idx < env.num_threads; ++thread_idx) {
    envs[thread_idx].my_shard_index += thread_idx;
    // Shuffle the shards, so that every thread produces different result.
    Rng rng(GetRandomSeed(env.seed + thread_idx));
    auto &shard_indices = shard_indices_per_thread[thread_idx];
    shard_indices.resize(env.total_shards);
    std::iota(shard_indices.begin(), shard_indices.end(), 0);
    std::shuffle(shard_indices.begin(), shard_indices.end(), rng);
    // Run the thread.
    threads[thread_idx] =
        std::thread(DistillTask, std::ref(envs[thread_idx]), shard_indices);
  }
  // Join threads.
  for (size_t thread_idx = 0; thread_idx < env.num_threads; thread_idx++) {
    threads[thread_idx].join();
  }
  return EXIT_SUCCESS;
}

}  // namespace centipede
