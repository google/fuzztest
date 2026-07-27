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

#include <cstdio>
#include <cstdlib>
#include <functional>

#include "absl/base/nullability.h"
#include "absl/types/span.h"
#include "./centipede/runner_interface.h"
#include "./common/defs.h"

namespace {

class AsyncFailingTargetRunnerCallbacks
    : public fuzztest::internal::RunnerCallbacks {
 public:
  bool Execute(void* input) override {
    to_fail_in_mutation = true;
    return true;
  }

  void* Mutate(void* inputs,
               const fuzztest::internal::ExecutionMetadata& metadata) override {
    if (to_fail_in_mutation) {
      fprintf(stderr, "Fail in mutation\n");
      std::abort();
    }
    return nullptr;
  }

  bool HasCustomMutator() const override { return true; }

  void* DeserializeInput(fuzztest::internal::ByteSpan input) override {
    return nullptr;
  }

  void SerializeInput(void* input,
                      const std::function<void(fuzztest::internal::ByteSpan)>&
                          bytes_sink) override {
    bytes_sink({0});
  }

  void FreeInput(void* input) override {}

 private:
  bool to_fail_in_mutation = false;
};

}  // namespace

int main(int argc, char** absl_nonnull argv) {
  AsyncFailingTargetRunnerCallbacks runner_callbacks;
  return fuzztest::internal::RunnerMain(argc, argv, runner_callbacks);
}
