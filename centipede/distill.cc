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

#include <cstdlib>
#include <thread>  // NOLINT(build/c++11)
#include <vector>

#include "absl/strings/str_cat.h"
#include "./centipede/defs.h"
#include "./centipede/environment.h"
#include "./centipede/feature_set.h"
#include "./centipede/logging.h"
#include "./centipede/shard_reader.h"
#include "./centipede/util.h"

namespace centipede {

void DistillThread(const Environment &env) {
  std::string log_line = absl::StrCat("DISTILL[S.", env.my_shard_index, "]: ");
  LOG(INFO) << log_line << VV(env.workdir) << VV(env.total_shards)
            << VV(env.binary_hash);
  // Shuffle the shards, read them one-by-one.
  Rng rng(GetRandomSeed(env.seed));
  std::vector<size_t> shard_idxs(env.total_shards);
  std::iota(shard_idxs.begin(), shard_idxs.end(), 0);
  std::shuffle(shard_idxs.begin(), shard_idxs.end(), rng);
  auto input_features_callback = [&](const ByteArray &input,
                                     FeatureVec &input_features) {
    VLOG(1) << log_line << VV(input.size()) << VV(input_features.size());
    // TODO(kcc): add the inputs to the distilled corpus here.
  };

  for (size_t shard_idx : shard_idxs) {
    LOG(INFO) << log_line << "reading shard " << shard_idx;
    ReadShard(env.MakeCorpusPath(shard_idx), env.MakeFeaturesPath(shard_idx),
              input_features_callback);
  }
}

int Distill(const Environment &env) {
  // Run `env.num_threads` independent distillation threads.
  std::vector<std::thread> threads(env.num_threads);
  std::vector<Environment> envs(env.num_threads, env);
  // Start the threads.
  for (size_t thread_idx = 0; thread_idx < env.num_threads; ++thread_idx) {
    envs[thread_idx].my_shard_index += thread_idx;
    threads[thread_idx] =
        std::thread(DistillThread, std::ref(envs[thread_idx]));
  }
  // Join threads.
  for (size_t thread_idx = 0; thread_idx < env.num_threads; thread_idx++) {
    threads[thread_idx].join();
  }
  return EXIT_SUCCESS;
}

}  // namespace centipede
