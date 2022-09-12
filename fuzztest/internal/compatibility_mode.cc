// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./fuzztest/internal/compatibility_mode.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include "absl/strings/str_format.h"
#include "./fuzztest/internal/logging.h"

namespace fuzztest::internal {

#ifdef FUZZTEST_COMPATIBILITY_MODE

static ExternalEngineCallback* external_engine_callback = nullptr;

void SetExternalEngineCallback(ExternalEngineCallback* callback) {
  external_engine_callback = callback;
}

ExternalEngineCallback* GetExternalEngineCallback() {
  return external_engine_callback;
}

// libFuzzer-style custom mutator interface for external engine.
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
                                          size_t max_size, unsigned int seed);

size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size, size_t max_size,
                               unsigned int seed) {
  ExternalEngineCallback* callback = GetExternalEngineCallback();
  FUZZTEST_INTERNAL_CHECK(
      callback,
      "External engine callback is unset while running the FuzzTest mutator.");
  const std::string mutated_data = callback->MutateData(
      std::string_view(reinterpret_cast<const char*>(data), size), max_size,
      seed);
  if (mutated_data.size() > max_size) {
    absl::FPrintF(GetStderr(),
                  "Mutated data is larger than the limit. Returning the "
                  "original data.\n");
    return size;
  }
  memcpy(data, mutated_data.data(), mutated_data.size());
  return mutated_data.size();
}

#endif  // FUZZTEST_COMPATIBILITY_MODE

}  // namespace fuzztest::internal
