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

// Centipede puzzle: easy-to-reach OOM.
// RUN: Run && SolutionIs OOM && ExpectOOM
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 3 && data[0] == 'O' && data[1] == 'O' && data[2] == 'M') {
    size_t huge_mem_size = (4ULL << 30) + (1ULL << 20);  // 4Gb + 1Mb
    char *ptr = new char[huge_mem_size];  // OOM here or one line below.
    memset(ptr, 42, huge_mem_size);
    fprintf(stderr, "%p\n", ptr);  // so that ptr it's not optimized away.
  }
  return 0;
}
