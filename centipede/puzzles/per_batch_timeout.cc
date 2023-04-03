// Copyright 2022 The Centipede Authors.
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

// Centipede puzzle: easy-to-reach per-batch timeout.
// clang-format off
// NOLINTNEXTLINE
// RUN: Run --batch_size=10 --timeout_per_input=2 --timeout_per_batch=7 && ExpectPerBatchTimeout
// clang-format on

#include <unistd.h>

#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  // Within the --timeout_per_input, but we have no solution, so the runner
  // should keep running us until it exceeds --timeout_per_batch, then report a
  // failure back to the engine.
  sleep(1);
  return 0;
}
