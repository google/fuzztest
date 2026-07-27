// Copyright 2026 The Centipede Authors.
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

#include "./centipede/crash_deduplication_test_util.h"

#include <cstdlib>
#include <string_view>

#include "absl/container/flat_hash_map.h"
#include "absl/types/span.h"
#include "./centipede/runner_result.h"
#include "./common/defs.h"

namespace fuzztest::internal {

bool FakeCentipedeCallbacks::Execute(std::string_view binary,
                                     absl::Span<const ByteSpan> inputs,
                                     BatchResult& batch_result) {
  batch_result.ClearAndResize(inputs.size());
  for (ByteSpan input : inputs) {
    auto it = crashing_inputs_.find(AsStringView(input));
    if (it == crashing_inputs_.end()) continue;
    batch_result.exit_code() = EXIT_FAILURE;
    batch_result.failure_signature() = it->second.signature;
    batch_result.failure_description() = it->second.description;
    return false;
  }
  return true;
}

}  // namespace fuzztest::internal
