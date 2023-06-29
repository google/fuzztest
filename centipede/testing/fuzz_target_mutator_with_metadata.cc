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

// A fuzz target used for testing the Centipede metadata API.
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <cstring>

static uint8_t *cmp_data_;
static size_t cmp_data_size_;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  return 0;
}

extern "C" int CentipedeCustomMutatorSetMetadata(const uint8_t *cmp_data,
                                                 size_t cmp_data_size) {
  cmp_data_size_ = cmp_data_size;
  if (cmp_data_size == 0) {
    if (cmp_data_ != nullptr) free(cmp_data_);
    cmp_data_ = nullptr;
    return 0;
  }
  cmp_data_ = static_cast<uint8_t *>(realloc(cmp_data_, cmp_data_size));
  if (cmp_data_ == nullptr) return -1;
  memcpy(cmp_data_, cmp_data, cmp_data_size);
  return 0;
}

// Copies cmp data as the mutant.
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size,
                                          size_t max_size, unsigned int seed) {
  assert(cmp_data_size_ == 0 || cmp_data_ != nullptr);
  size_t mutant_size = cmp_data_size_ < max_size ? cmp_data_size_ : max_size;
  memcpy(data, cmp_data_, mutant_size);
  return mutant_size;
}
