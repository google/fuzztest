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

#include <cstdlib>
#include <functional>
#include <vector>

#include "absl/base/nullability.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "./centipede/mutation_input.h"
#include "./centipede/runner_interface.h"
#include "./common/defs.h"

ABSL_FLAG(bool, simulate_failure, false,
          "If true, the binary will return EXIT_FAILURE to simulate a "
          "failure.");

using ::centipede::ByteSpan;

class CustomMutatorRunnerCallbacks : public centipede::RunnerCallbacks {
 public:
  bool Execute(ByteSpan input) override { return true; }

  bool HasCustomMutator() const override { return true; }

  bool Mutate(const std::vector<centipede::MutationInputRef>& inputs,
              size_t num_mutants,
              std::function<void(ByteSpan)> new_mutant_callback) override {
    size_t i = 0;
    for (centipede::MutationInputRef input : inputs) {
      if (i++ >= num_mutants) break;
      // Just return the original input as a mutant.
      new_mutant_callback(input.data);
    }
    return true;
  }
};

int main(int argc, char** absl_nonnull argv) {
  absl::ParseCommandLine(argc, argv);
  if (absl::GetFlag(FLAGS_simulate_failure)) {
    return EXIT_FAILURE;
  }
  CustomMutatorRunnerCallbacks runner_callbacks;
  return centipede::RunnerMain(argc, argv, runner_callbacks);
}
