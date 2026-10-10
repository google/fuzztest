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

#include <cstddef>
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
  for (size_t i = 0; i < inputs.size(); ++i) {
    auto it = crashing_inputs_.find(AsStringView(inputs[i]));
    if (it == crashing_inputs_.end()) continue;
    batch_result.num_outputs_read() = i;
    batch_result.exit_code() = EXIT_FAILURE;
    batch_result.failure_signature() = it->second.signature;
    batch_result.failure_description() = it->second.description;
    return false;
  }
  batch_result.num_outputs_read() = inputs.size();
  return true;
}

}  // namespace fuzztest::internal
