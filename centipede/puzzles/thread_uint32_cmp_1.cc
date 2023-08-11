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

// Centipede puzzle: one 4-byte cmp, in a separate thread.
// We should be able to solve it w/o cmp features *or* w/o auto dictionary.
// RUN: Run && SolutionIs Fuzz
// RUN: Run --use_auto_dictionary=0 && SolutionIs Fuzz
// TODO(b/295378866): Centipede runner currently fails to collect dictionary
// entries from merged threads, so if we disable cmp features we can't crack
// this puzzle. Enable "Run --use_cmp_features=0 && SolutionIs Fuzz"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <thread>  // NOLINT(build/c++11)

// non-const, to avoid compiler optimization.
static char expected_data[] = "Fuzz";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::thread t([&]() {
    uint32_t value, expected_value;
    if (size == sizeof(value)) {
      memcpy(&value, data, sizeof(value));
      memcpy(&expected_value, expected_data, sizeof(expected_value));
      if (value == expected_value) abort();
    }
  });
  t.join();
  return 0;
}
