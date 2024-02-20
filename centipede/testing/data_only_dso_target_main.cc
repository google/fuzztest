// Copyright 2024 The Centipede Authors.
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
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "./centipede/testing/data_only_dso_target_lib.h"

// A fuzz target that uses data from a different DSO.
extern "C" int __attribute__((optnone)) LLVMFuzzerTestOneInput(
    const uint8_t* data, size_t size) {
  if (size != crash_input_size) return -1;
  if (memcmp(crash_input, data, size) == 0) std::abort();
  return 0;
}
