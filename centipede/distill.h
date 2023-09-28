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

#ifndef THIRD_PARTY_CENTIPEDE_DISTILL_H_
#define THIRD_PARTY_CENTIPEDE_DISTILL_H_

#include <cstddef>
#include <vector>

#include "./centipede/environment.h"

namespace centipede {

// Runs one independent distillation task. Reads shards in the order specified
// by `shard_indices`, distills inputs from them and writes the result to
// `WorkDir{env}.DistilledPath()`. Every task gets its own `env.my_shard_index`,
// and so every task creates its own independent distilled corpus file.
void DistillTask(const Environment &env,
                 const std::vector<size_t> &shard_indices);

// Runs `env.num_threads` independent distill tasks in separate threads.
// Returns EXIT_SUCCESS.
int Distill(const Environment &env);

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_DISTILL_H_
