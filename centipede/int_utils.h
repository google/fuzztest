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

#ifndef THIRD_PARTY_CENTIPEDE_INT_UTILS_H_
#define THIRD_PARTY_CENTIPEDE_INT_UTILS_H_

#include <cstdint>

namespace centipede {

// Computes a hash of `bits`. The purpose is to use the result for XOR-ing with
// some other values, such that all resulting bits look random.
inline uint64_t Hash64Bits(uint64_t bits) {
  // This particular prime number seems to mix bits well.
  // TODO(kcc): find a more scientific way to mix bits, e.g. switch to Murmur.
  constexpr uint64_t kPrime = 13441014529ULL;
  return bits * kPrime;
}

// Accumulates the 32-bit CRC for `previous` with `input`.
inline uint32_t CRC32(uint32_t previous, uint32_t input) {
#if __ARM_FEATURE_CRC32
  return __builtin_arm_crc32w(previous, input);
#else
  return __builtin_ia32_crc32si(previous, input);
#endif
}

// Returns `bits` rotated left by `n`.
inline uint64_t RotateLeft(uint64_t bits, uint64_t n) {
  return (bits << n) | (bits >> (64 - n));
}

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_INT_UTILS_H_
