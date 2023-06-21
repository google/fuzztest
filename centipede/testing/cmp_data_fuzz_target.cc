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

// A fuzz target used for testing the Centipede cmp data API.
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <utility>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return 0;
}

static uint8_t *cmp_data;
static size_t cmp_data_size;

// Copies cmp data as the mutant.
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                          size_t max_size, unsigned int seed) {
  size_t mutant_size = cmp_data_size < max_size ? cmp_data_size : max_size;
  memcpy(data, cmp_data, mutant_size);
  return mutant_size;
}

extern "C" int CentipedeCustomMutatorSetCmpData(const uint8_t *data,
                                                size_t size) {
  cmp_data_size = size;
  if (size == 0) {
    if (cmp_data) free(cmp_data);
    cmp_data = nullptr;
    return 0;
  }
  cmp_data = static_cast<uint8_t *>(realloc(cmp_data, size));
  if (cmp_data == nullptr) return -1;
  memcpy(cmp_data, data, size);
  return 0;
}
