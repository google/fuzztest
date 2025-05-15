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

#include "./centipede/dispatcher.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

namespace {

const char* GetBinaryId() { return "some_binary_id"; }

void ListTests() { FuzzTestDispatcherEmitTestName("some_test"); }

void CheckIfTestIdIsCorrect() {
  [[maybe_unused]] static bool check_once = [] {
    const char* test_name = FuzzTestDispatcherGetTestName();
    if (test_name == nullptr || strcmp(test_name, "some_test") != 0) {
      fprintf(stderr, "Unexpected test name: %s\n", test_name);
      std::_Exit(1);
    }
    return true;
  }();
}

void GetSeeds() {
  CheckIfTestIdIsCorrect();
  FuzzTestDispatcherEmitSeed("seed", 6);
}

void Mutate(const FuzzTestDispatcherMutateInput* mutate_inputs,
            size_t num_mutate_inputs, size_t num_mutant, int shrink) {
  CheckIfTestIdIsCorrect();

  bool has_seed = false;
  bool has_mutant_1 = false;
  bool has_mutant_2 = false;
  fprintf(stderr, "# of mutate inputs: %zu\n", num_mutate_inputs);
  for (size_t i = 0; i < num_mutate_inputs; ++i) {
    fprintf(stderr, "Mutate input: %.*s\n",
            static_cast<int>(mutate_inputs[i].input_size),
            reinterpret_cast<const char*>(mutate_inputs[i].input));
    if (strncmp(reinterpret_cast<const char*>(mutate_inputs[i].input), "seed",
                mutate_inputs[i].input_size) == 0) {
      has_seed = true;
    }
    if (strncmp(reinterpret_cast<const char*>(mutate_inputs[i].input),
                "mutant_1", mutate_inputs[i].input_size) == 0) {
      has_mutant_1 = true;
    }
    if (strncmp(reinterpret_cast<const char*>(mutate_inputs[i].input),
                "mutant_2", mutate_inputs[i].input_size) == 0) {
      has_mutant_2 = true;
    }
  }

  for (size_t i = 0; i < num_mutant; ++i) {
    if (has_mutant_2) {
      FuzzTestDispatcherEmitMutant("mutant_3", 8);
    } else if (has_mutant_1) {
      FuzzTestDispatcherEmitMutant("mutant_2", 8);
    } else if (has_seed) {
      FuzzTestDispatcherEmitMutant("mutant_1", 8);
    } else {
      FuzzTestDispatcherEmitMutant("bad input", 9);
    }
  }
}

void Execute(const void* input, size_t size) {
  std::vector<FuzzTestDispathcerCounterId> feedback;
  if (strncmp(reinterpret_cast<const char*>(input), "seed", size) == 0) {
    feedback.push_back(0);
    feedback.push_back(1);
    feedback.push_back(2);
  } else if (strncmp(reinterpret_cast<const char*>(input), "mutant_1", size) ==
             0) {
    feedback.push_back(3);
    feedback.push_back(4);
  } else if (strncmp(reinterpret_cast<const char*>(input), "mutant_2", size) ==
             0) {
    feedback.push_back(5);
  } else if (strncmp(reinterpret_cast<const char*>(input), "mutant_3", size) ==
             0) {
    FuzzTestDispatcherEmitFailure(kFuzzTestInputFailure,
                                  "some_failure_description", "SOME_SIGNATURE",
                                  14);
    std::_Exit(1);
  } else {
    FuzzTestDispatcherEmitFailure(
        kFuzzTestSetupFailure,
        "unexpected input that is not seed or mutant from seed",
        "OTHER_SIGNATURE", 15);
    std::_Exit(1);
  }

  FuzzTestDispatcherEmitFeedbackAs1BitCounters(feedback.data(),
                                               feedback.size());
}

}  // namespace

int main(int argc, char** argv) {
  if (!FuzzTestDispatcherIsEnabled()) return 0;
  FuzzTestDispatcherCallbacks callbacks = {
      &GetBinaryId, &ListTests, &GetSeeds, &Mutate, &Execute,
  };
  return FuzzTestDispatcherRun(&callbacks);
}
