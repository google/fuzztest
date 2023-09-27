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

#include "./centipede/centipede_default_callbacks.h"

#include <cstddef>
#include <string_view>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/defs.h"
#include "./centipede/environment.h"
#include "./centipede/logging.h"  // IWYU pragma: keep
#include "./centipede/mutation_input.h"
#include "./centipede/runner_result.h"

namespace centipede {

CentipedeDefaultCallbacks::CentipedeDefaultCallbacks(const Environment &env)
    : CentipedeCallbacks(env) {
  for (const auto &dictionary_path : env_.dictionary) {
    LoadDictionary(dictionary_path);
  }

  if (env_.has_input_wildcards) {
    LOG(INFO) << "Disabling custom mutator for standalone target";
    custom_mutator_is_usable_ = false;
  }
}

bool CentipedeDefaultCallbacks::Execute(std::string_view binary,
                                        const std::vector<ByteArray> &inputs,
                                        BatchResult &batch_result) {
  return ExecuteCentipedeSancovBinaryWithShmem(binary, inputs, batch_result) ==
         0;
}

size_t CentipedeDefaultCallbacks::GetSeeds(size_t num_seeds,
                                           std::vector<ByteArray> &seeds) {
  seeds.resize(num_seeds);
  if (GetSeedsViaExternalBinary(env_.binary, num_seeds, seeds))
    return num_seeds;
  else
    return CentipedeCallbacks::GetSeeds(num_seeds, seeds);
}

void CentipedeDefaultCallbacks::Mutate(
    const std::vector<MutationInputRef> &inputs, size_t num_mutants,
    std::vector<ByteArray> &mutants) {
  mutants.resize(num_mutants);
  if (num_mutants == 0) return;
  // Try to use the custom mutator if it hasn't been disabled.
  if (custom_mutator_is_usable_.value_or(true)) {
    if (MutateViaExternalBinary(env_.binary, inputs, mutants)) {
      if (!custom_mutator_is_usable_.has_value()) {
        LOG(INFO) << "Custom mutator detected: will use it";
        custom_mutator_is_usable_ = true;
      }
      if (!mutants.empty()) return;
      LOG_FIRST_N(WARNING, 5)
          << "Custom mutator returned no mutants: falling back to internal "
             "default mutator";
    } else {
      LOG(WARNING) << "Custom mutator undetected or misbehaving:";
      CHECK(!custom_mutator_is_usable_.has_value())
          << "Custom mutator is unreliable, aborting";
      LOG(WARNING) << "Falling back to internal default mutator";
      custom_mutator_is_usable_ = false;
    }
  }
  // Fallback of the internal mutator.
  CentipedeCallbacks::Mutate(inputs, num_mutants, mutants);
}

}  // namespace centipede
