// Copyright 2025 The Centipede Authors.
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

// Centipede puzzle: one 4-byte switch.
// RUN: Run --max_len=10 --use_cmp_features=0 && ExpectInLog "deadbeef found!"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// Needed to avoid turning switch into regular comparisons, which are traced in
// different ways.
__attribute__((optnone)) extern "C" int LLVMFuzzerTestOneInput(
    const uint8_t* data, size_t size) {
  if (size == 4) {
    uint32_t val = 0;
    std::memcpy(&val, data, size);
    switch (val) {
      case 0xdeadbeef:
        std::fprintf(stderr, "deadbeef found!\n");
        std::abort();
      // Add other branches to avoid optimizing the switch into regular
      // comparisons.
      case 0x12345678:
        break;
      case 0xabababab:
        break;
      default:
        break;
    }
  }
  return 0;
}
