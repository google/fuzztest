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

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

#include "./centipede/runner_interface.h"

using centipede::ByteSpan;

class SeededRunnerCallbacks : public centipede::RunnerCallbacks {
 public:
  bool Execute(ByteSpan input) override {
    // Should not be called in the test, but return true anyway.
    return true;
  }

  void GetSeeds(std::function<void(ByteSpan)> seed_callback) override {
    constexpr size_t kNumAvailSeeds = 10;
    for (size_t i = 0; i < kNumAvailSeeds; ++i)
      seed_callback({static_cast<uint8_t>(i)});
  }

  bool Mutate(const std::vector<centipede::MutationInputRef> &inputs,
              size_t num_mutants,
              std::function<void(ByteSpan)> new_mutant_callback) override {
    // Should not be called in the test, but return a dummy mutant anyway.
    new_mutant_callback({0});
    return true;
  }
};

int main(int argc, char **argv) {
  SeededRunnerCallbacks runner_callbacks;
  return centipede::RunnerMain(argc, argv, runner_callbacks);
}
