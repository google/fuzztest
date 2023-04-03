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

// Centipede puzzle: easy-to-reach per-input timeout.
// RUN: Run --timeout_per_input=2 && SolutionIs SLO && ExpectPerInputTimeout

#include <unistd.h>

#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 3 && data[0] == 'S' && data[1] == 'L' && data[2] == 'O') {
    sleep(1000);  // Dies with timeout.
  }
  return 0;
}
