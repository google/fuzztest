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

#ifndef THIRD_PARTY_CENTIPEDE_MUTATION_DATA_H_
#define THIRD_PARTY_CENTIPEDE_MUTATION_DATA_H_

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

  // For testing.
  bool operator==(const Mutant& other) const { return data == other.data; }
};

// A reference counterpart of `Mutant`. Needed because it can be constructed
// from std::string and/or by the C-only dispatcher without copying the
// underlying data.
struct MutantRef {
  ByteSpan data;
};

inline std::vector<ByteArray> GetDataFromMutants(
    const std::vector<Mutant>& mutants) {
  std::vector<ByteArray> results;
  results.reserve(mutants.size());
  for (const auto& mutant : mutants) {
    results.push_back(mutant.data);
  }
  return results;
}

}  // namespace fuzztest::internal

#endif  // THIRD_PARTY_CENTIPEDE_MUTATION_DATA_H_
