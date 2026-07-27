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

#ifndef FUZZTEST_CENTIPEDE_CRASH_DEDUPLICATION_TEST_UTIL_H_
#define FUZZTEST_CENTIPEDE_CRASH_DEDUPLICATION_TEST_UTIL_H_

#include <string>
#include <string_view>
#include <utility>

#include "absl/container/flat_hash_map.h"
#include "absl/types/span.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/environment.h"
#include "./centipede/runner_result.h"
#include "./centipede/stop.h"
#include "./common/defs.h"

namespace fuzztest::internal {

class FakeCentipedeCallbacks : public CentipedeCallbacks {
 public:
  struct Crash {
    std::string signature;
    std::string description;
  };

  explicit FakeCentipedeCallbacks(
      const Environment& env,
      absl::flat_hash_map<std::string, Crash> crashing_inputs)
      : CentipedeCallbacks(env, internal_stop_condition_),
        crashing_inputs_(std::move(crashing_inputs)) {}

  bool Execute(std::string_view binary, absl::Span<const ByteSpan> inputs,
               BatchResult& batch_result) override;

 private:
  absl::flat_hash_map<std::string, Crash> crashing_inputs_;
  StopCondition internal_stop_condition_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_CENTIPEDE_CRASH_DEDUPLICATION_TEST_UTIL_H_
