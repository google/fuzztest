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

// Centipede puzzle: 4 independent compares setting a mask.
// RUN: Run && SolutionIs FUZZ
#include <cstddef>
#include <cstdint>
#include <cstdlib>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  int mask = 0;
  if (size > 4) return 0;
  if (size > 0 && data[0] == 'F') mask |= 1;
  if (size > 1 && data[1] == 'U') mask |= 2;
  if (size > 2 && data[2] == 'Z') mask |= 4;
  if (size > 3 && data[3] == 'Z') mask |= 8;
  if (mask == 15) {
    abort();
  }
  return 0;
}
