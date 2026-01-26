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

#include <cstdlib>

#include "./centipede/runner_interface.h"
#include "./common/defs.h"

namespace {

class AsyncFailingTargetRunnerCallbacks
    : public fuzztest::internal::RunnerCallbacks {
 public:
  bool Execute(fuzztest::internal::ByteSpan input) override {
    to_fail_in_mutation = true;
    return true;
  }

  bool Mutate(const std::vector<fuzztest::internal::MutationInputRef>& inputs,
              size_t num_mutants,
              std::function<void(fuzztest::internal::ByteSpan)>
                  new_mutant_callback) override {
    if (to_fail_in_mutation) {
      fprintf(stderr, "Fail in mutation\n");
      std::abort();
    }
    return true;
  }

  bool HasCustomMutator() const override { return true; }

 private:
  bool to_fail_in_mutation = false;
};

}  // namespace

int main(int argc, char** absl_nonnull argv) {
  AsyncFailingTargetRunnerCallbacks runner_callbacks;
  return fuzztest::internal::RunnerMain(argc, argv, runner_callbacks);
}
