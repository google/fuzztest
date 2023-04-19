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

// A simple fuzz target that contains bugs detectable by different sanitizers.
// For now, asan and msan.
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <thread>  // NOLINT

[[maybe_unused]] static volatile void *sink;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size != 3) return 0;  // Make bugs easy to discover.
  // "uaf" => heap-use-after-free
  if (data[0] == 'u' && data[1] == 'a' && data[2] == 'f') {
    int *x = new int;
    fprintf(stderr, "uaf %p\n", x);
    sink = x;
    delete x;
    *x = 0;
  }
  // "uum" => use of uninitialized memory
  if (data[0] == 'u' && data[1] == 'u' && data[2] == 'm') {
    int *x = new int[10];
    fprintf(stderr, "uum %p\n", x);
    if (x[5]) fprintf(stderr, "inside uum-controlled condition\n");
    delete[] x;
  }
  // "rac" => data race
  if (data[0] == 'r' && data[1] == 'a' && data[2] == 'c') {
    int racy_var = 0;
    std::thread t([&racy_var]() { ++racy_var; });
    ++racy_var;
    t.join();
  }
  return 0;
}
