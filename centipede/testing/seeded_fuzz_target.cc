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

#include "absl/base/nullability.h"
#include "./centipede/runner_interface.h"
#include "./common/defs.h"

using fuzztest::internal::ByteSpan;

class SeededRunnerCallbacks : public fuzztest::internal::RunnerCallbacks {
 public:
  bool Execute(void* input) override {
    // Should not be called in the test, but return true anyway.
    return true;
  }

  void GetPresetSeedInputs(
      const std::function<void(void*)>& seed_callback) override {
    constexpr size_t kNumAvailSeeds = 10;
    for (size_t i = 0; i < kNumAvailSeeds; ++i)
      seed_callback(reinterpret_cast<void*>(
          new fuzztest::internal::ByteArray{static_cast<uint8_t>(i)}));
  }

  bool HasCustomMutator() const override { return false; }

  void* DeserializeInput(fuzztest::internal::ByteSpan input) override {
    return reinterpret_cast<void*>(
        new fuzztest::internal::ByteArray{input.begin(), input.end()});
  }

  void SerializeInput(void* input,
                      const std::function<void(fuzztest::internal::ByteSpan)>&
                          bytes_sink) override {
    const auto* ba =
        reinterpret_cast<const fuzztest::internal::ByteArray*>(input);
    bytes_sink(*ba);
  }

  void FreeInput(void* input) override {
    delete reinterpret_cast<const fuzztest::internal::ByteArray*>(input);
  }
};

int main(int argc, char** absl_nonnull argv) {
  SeededRunnerCallbacks runner_callbacks;
  return fuzztest::internal::RunnerMain(argc, argv, runner_callbacks);
}
