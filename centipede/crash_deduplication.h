// Copyright 2025 The Centipede Authors.
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

#ifndef FUZZTEST_CENTIPEDE_CRASH_DEDUPLICATION_H_
#define FUZZTEST_CENTIPEDE_CRASH_DEDUPLICATION_H_

#include <cstddef>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "./centipede/workdir.h"

namespace fuzztest::internal {

struct CrashDetails {
  std::string input_signature;
  std::string description;
  std::string input_path;
};

// Returns a map of crash signatures to crash details for crashes in the
// workdir. Only one crash per signature is returned, selected arbitrarily.
absl::flat_hash_map<std::string, CrashDetails> GetCrashesFromWorkdir(
    const WorkDir& workdir, size_t total_shards);

}  // namespace fuzztest::internal

#endif  // FUZZTEST_CENTIPEDE_CRASH_DEDUPLICATION_H_
