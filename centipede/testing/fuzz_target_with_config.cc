// Copyright 2024 The Centipede Authors.
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
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "absl/base/nullability.h"
#include "./centipede/mutation_input.h"
#include "./centipede/runner_interface.h"
#include "./common/defs.h"

using ::centipede::ByteSpan;

class FakeSerializedConfigRunnerCallbacks : public centipede::RunnerCallbacks {
 public:
  bool Execute(ByteSpan input) override { return true; }

  bool Mutate(const std::vector<centipede::MutationInputRef> &inputs,
              size_t num_mutants,
              std::function<void(ByteSpan)> new_mutant_callback) override {
    return true;
  }

  std::string GetSerializedTargetConfig() override {
    return "fake serialized config";
  }
};

int main(int argc, absl::Nonnull<char **> argv) {
  if (argc >= 2 && std::strcmp(argv[1], "--simulate_failure") == 0) {
    return EXIT_FAILURE;
  }
  FakeSerializedConfigRunnerCallbacks runner_callbacks;
  return centipede::RunnerMain(argc, argv, runner_callbacks);
}
