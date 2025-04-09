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

#include <cstdlib>
#include <string>

#include "absl/base/nullability.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "./centipede/runner_interface.h"
#include "./common/defs.h"

ABSL_FLAG(bool, simulate_failure, false,
          "If true, the binary will return EXIT_FAILURE to simulate a "
          "failure.");

using fuzztest::internal::ByteSpan;

class FakeSerializedConfigRunnerCallbacks
    : public fuzztest::internal::RunnerCallbacks {
 public:
  // Trivial implementations for the execution and mutation logic, even though
  // they should not be used in the tests that use this test binary.
  bool Execute(ByteSpan input) override { return true; }
  bool HasCustomMutator() const override { return false; }

  std::string GetSerializedTargetConfig() override {
    return "fake serialized config";
  }
};

int main(int argc, char** absl_nonnull argv) {
  absl::ParseCommandLine(argc, argv);
  if (absl::GetFlag(FLAGS_simulate_failure)) {
    return EXIT_FAILURE;
  }
  FakeSerializedConfigRunnerCallbacks runner_callbacks;
  return fuzztest::internal::RunnerMain(argc, argv, runner_callbacks);
}
