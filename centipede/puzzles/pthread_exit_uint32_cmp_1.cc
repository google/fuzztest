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

// Centipede puzzle: one 4-byte cmp, in a separate thread using pthread
// interface. We should be able to solve it w/o cmp features *or* w/o auto
// dictionary.
//
// RUN: Run && SolutionIs Fuzz
// RUN: Run --use_auto_dictionary=0 && SolutionIs Fuzz
// RUN: Run --use_cmp_features=0 && SolutionIs Fuzz

#include <pthread.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>

// non-const, to avoid compiler optimization.
static char expected_data[] = "Fuzz";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  pthread_t pt;
  struct ThreadArg {
    const uint8_t *data;
    size_t size;
  } arg = {.data = data, .size = size};
  auto pt_entry = +[](const ThreadArg *thread_arg) {
    uint32_t value, expected_value;
    if (thread_arg->size == sizeof(value)) {
      memcpy(&value, thread_arg->data, sizeof(value));
      memcpy(&expected_value, expected_data, sizeof(expected_value));
      if (value == expected_value) abort();
      pthread_exit(nullptr);
    }
  };
  if (pthread_create(&pt, nullptr,
                     reinterpret_cast<void *(*)(void *)>(pt_entry), &arg) != 0)
    return 1;
  if (pthread_join(pt, nullptr) != 0) return 1;
  return 0;
}
