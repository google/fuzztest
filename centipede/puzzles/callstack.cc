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

// Centipede puzzle: crashes when the input triggers a specific call stack.
// Functions F0, FA, FB, FC, FD call themselves recursively to depth up to four.
// Input data bytes are used to choose which function is called.
// All functions but F0 also modify `g_result`.
// The puzzle can be solved if the call sequence is FA->FB->FC->FD.

// RUN: Run
// RUN: SolutionIs ABCD
#include <cstddef>
#include <cstdint>

namespace {

// Don't let the compiler be too smart.
static inline void BreakOptimization(const void *arg) {
  __asm__ __volatile__("" : : "r"(arg) : "memory");
}

using F = void (*)(const uint8_t *data, size_t idx);
extern F table[256];

void F0(const uint8_t *data, size_t idx) {
  if (idx + 1 < 4) table[data[idx + 1]](data, idx + 1);
  BreakOptimization(data);
}

constexpr uintptr_t kMagicA = 0xAAAA;
constexpr uintptr_t kMagicB = 0xBBBB;
constexpr uintptr_t kMagicC = 0xCCCC;
constexpr uintptr_t kMagicD = 0xDDDD;
uintptr_t g_result;

void FA(const uint8_t *data, size_t idx) {
  g_result |= kMagicA << (idx * 16);
  if (idx + 1 < 4) table[data[idx + 1]](data, idx + 1);
  BreakOptimization(data);
}

void FB(const uint8_t *data, size_t idx) {
  g_result |= kMagicB << (idx * 16);
  if (idx + 1 < 4) table[data[idx + 1]](data, idx + 1);
  BreakOptimization(data);
}

void FC(const uint8_t *data, size_t idx) {
  g_result |= kMagicC << (idx * 16);
  if (idx + 1 < 4) table[data[idx + 1]](data, idx + 1);
  BreakOptimization(data);
}

void FD(const uint8_t *data, size_t idx) {
  g_result |= kMagicD << (idx * 16);
  if (idx + 1 < 4) table[data[idx + 1]](data, idx + 1);
  BreakOptimization(data);
}

// Table of 256 function pointers.
// Most values are `F0`. The values at indices 'A', 'B', 'C' and 'D'
// are FA, FB, FC, FD respectively.
// clang-format off
F table[256] = {
  F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,  // 0-15
  F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,  // 16-31
  F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,  // 32-47
  F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,  // 48-63
  // Special values FA, FB, FC, FD in this line:
  F0, FA, FB, FC, FD, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,  // 64-79
  F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,
  F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,
  F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,
  F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,
  F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,
  F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,
  F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,
  F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,
  F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,
  F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,
  F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0, F0,
};
// clang-format on

}  // namespace

// Causes div-by-zero if the input is exactly 'ABCD'.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  g_result = 0;
  if (size != 4) return 0;
  table[data[0]](data, 0);
  g_result = 1000 / (0xDDDDCCCCBBBBAAAA - g_result);
  return 0;
}
