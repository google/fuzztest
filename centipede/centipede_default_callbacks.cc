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

#include "./centipede/centipede_interface.h"
#include "./centipede/defs.h"
#include "./centipede/environment.h"
#include "./centipede/logging.h"

namespace centipede {

CentipedeDefaultCallbacks::CentipedeDefaultCallbacks(const Environment &env)
    : CentipedeCallbacks(env) {
  for (const auto &dictionary_path : env_.dictionary) {
    LoadDictionary(dictionary_path);
  }

  // TODO(b/267096672): This logic is unreliable: improve.
  // Check if a custom mutator is available in the target.
  LOG(INFO) << "Detecting custom mutator in target...";
  std::vector<ByteArray> mutants(1);
  const bool external_mutator_ran =
      MutateViaExternalBinary(env_.binary, /*inputs=*/{{.data = {0}}}, mutants);
  if (external_mutator_ran && mutants.size() == 1 && !mutants.front().empty()) {
    custom_mutator_is_usable_ = true;
    LOG(INFO) << "Custom mutator detected: will use it";
  } else {
    LOG(INFO) << "Custom mutator undetected or misbehaving: will use built-in";
    LOG(INFO) << VV(external_mutator_ran) << VV(mutants.size());
    LOG_IF(INFO, !mutants.empty()) << VV(mutants.front().size());
  }
}

bool CentipedeDefaultCallbacks::Execute(std::string_view binary,
                                        const std::vector<ByteArray> &inputs,
                                        BatchResult &batch_result) {
  return ExecuteCentipedeSancovBinaryWithShmem(binary, inputs, batch_result) ==
         0;
}

void CentipedeDefaultCallbacks::Mutate(
    const std::vector<MutationInputRef> &inputs, size_t num_mutants,
    std::vector<ByteArray> &mutants) {
  mutants.resize(num_mutants);
  if (custom_mutator_is_usable_) {
    CHECK(MutateViaExternalBinary(env_.binary, inputs, mutants))
        << "Custom mutator in " << env_.binary << " failed, aborting";
    return;
  }
  // No custom mutator.
  CentipedeCallbacks::Mutate(inputs, num_mutants, mutants);
}

}  // namespace centipede
