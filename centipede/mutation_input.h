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

// Data types used for mutation.
//
// This library is for both engine and runner.

#ifndef THIRD_PARTY_CENTIPEDE_MUTATION_INPUT_H_
#define THIRD_PARTY_CENTIPEDE_MUTATION_INPUT_H_

#include <cstddef>
#include <vector>

#include "./centipede/execution_metadata.h"
#include "./common/defs.h"

namespace fuzztest::internal {

// {data (required), metadata (optional)} reference pairs as mutation inputs.
struct MutationInputRef {
  const ByteArray &data;
  const ExecutionMetadata *metadata = nullptr;
};

inline std::vector<ByteArray> CopyDataFromMutationInputRefs(
    const std::vector<MutationInputRef> &inputs) {
  std::vector<ByteArray> results;
  results.reserve(inputs.size());
  for (const auto &input : inputs) results.push_back(input.data);
  return results;
}

inline std::vector<MutationInputRef> GetMutationInputRefsFromDataInputs(
    const std::vector<ByteArray> &inputs) {
  std::vector<MutationInputRef> results;
  results.reserve(inputs.size());
  for (const auto &input : inputs) results.push_back({/*data=*/input});
  return results;
}

// Represents a mutation result.
struct Mutant {
  // The mutant `data`.
  ByteArray data;
  // The index of the input used to mutate into `data`. The index can be
  // interpreted in different ways depending on the context: In mutation batch
  // results, it means the index in the batch input. Once processed by the
  // engine it means the index of the in-memory corpus.
  size_t origin = kOriginNone;
  // A special `origin` value to indicate that the mutant has no origin.
  static constexpr size_t kOriginNone = static_cast<size_t>(-1);

  bool operator==(const Mutant& other) const {
    return data == other.data && origin == other.origin;
  }
};

}  // namespace fuzztest::internal

#endif  // THIRD_PARTY_CENTIPEDE_MUTATION_INPUT_H_
