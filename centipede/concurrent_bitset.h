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

// This library defines the concepts "fuzzing feature" and "feature domain".
// It is used by Centipede, and it can be used by fuzz runners to
// define their features in a way most friendly to Centipede.
// Fuzz runners do not have to use this file nor to obey the rules defined here.
// But using this file and following its rules is the simplest way if you want
// Centipede to understand the details about the features generated by the
// runner.
//
// This library must not depend on anything other than libc so that fuzz targets
// using it doesn't gain redundant coverage. For the same reason this library
// uses raw __builtin_trap instead of CHECKs.
// We make an exception for <algorithm> for std::sort/std::unique,
// since <algorithm> is very lightweight.
// This library is also header-only, with all functions defined as inline.

#ifndef THIRD_PARTY_CENTIPEDE_CONCURRENT_BITSET_H_
#define THIRD_PARTY_CENTIPEDE_CONCURRENT_BITSET_H_

#include <stddef.h>
#include <string.h>

// WARNING!!!: Be very careful with what STL headers or other dependencies you
// add here. This header needs to remain mostly bare-bones so that we can
// include it into runner.
#include <climits>
#include <cstdint>
#include <functional>

#include "absl/base/const_init.h"
#include "./centipede/concurrent_byteset.h"

namespace fuzztest::internal {

// A fixed-size bitset with a lossy concurrent set() function.
// kSize (in bits) must be a multiple of 2**16.
//
// IMPORTANT!!! Objects of this class should only be constructed with static
// storage duration. This is because the class has intentionally uninitialized
// direct and transitive data members that rely on static initialization in the
// compiled process image.
template <size_t kSizeInBits>
class ConcurrentBitSet {
 public:
  static_assert((kSizeInBits % (1<<16)) == 0);

  // Creates a ConcurrentBitSet with static storage duration.
  explicit constexpr ConcurrentBitSet(absl::ConstInitType)
      : lines_{absl::kConstInit} {}

  // Clears the bit set.
  void clear() {
    memset(words_, 0, sizeof(words_));
    lines_.clear();
  }

  // Sets the bit `idx % kSizeInBits`.
  // set() can be called concurrently with another set().
  // If several threads race to update adjacent bits,
  // the update may be lost (i.e. set() is lossy).
  // We could use atomic set-bit instructions to make it non-lossy,
  // but it is going to be too expensive.
  void set(size_t idx) {
    idx %= kSizeInBits;
    size_t word_idx = idx / kBitsInWord;
    size_t bit_idx = idx % kBitsInWord;
    size_t line_idx = word_idx / kWordsInLine;
    lines_.Set(line_idx, 1);
    word_t mask = 1ULL << bit_idx;
    word_t word = __atomic_load_n(&words_[word_idx], __ATOMIC_RELAXED);
    if (!(word & mask)) {
      word |= mask;
      __atomic_store_n(&words_[word_idx], word, __ATOMIC_RELAXED);
    }
  }

  // Gets the bit at `idx % kSizeInBits`.
  uint8_t get(size_t idx) {
    idx %= kSizeInBits;
    size_t word_idx = idx / kBitsInWord;
    size_t bit_idx = idx % kBitsInWord;
    word_t word = __atomic_load_n(&words_[word_idx], __ATOMIC_RELAXED);
    word_t mask = 1ULL << bit_idx;
    return (word & mask) != 0;
  }

  // Calls `action(index)` for every index of a non-zero bit in the set,
  // then sets all those bits to zero.
  __attribute__((noinline)) void ForEachNonZeroBit(
      const std::function<void(size_t idx)> &action) {
    // Iterates over all non-empty lines.
    lines_.ForEachNonZeroByte([&](size_t idx, uint8_t value) {
      size_t word_idx_beg = idx * kWordsInLine;
      size_t word_idx_end = word_idx_beg + kWordsInLine;
      ForEachNonZeroBit(action, word_idx_beg, word_idx_end);
    });
  }

 private:
  // Iterates over the range of words [`word_idx_beg`, `word_idx_end`).
  void ForEachNonZeroBit(const std::function<void(size_t idx)> &action,
                         size_t word_idx_beg, size_t word_idx_end) {
    for (size_t word_idx = word_idx_beg; word_idx < word_idx_end; ++word_idx) {
      if (word_t word = words_[word_idx]) {
        words_[word_idx] = 0;
        do {
          size_t bit_idx = __builtin_ctzll(word);
          action(word_idx * kBitsInWord + bit_idx);
          word_t mask = 1ULL << bit_idx;
          word &= ~mask;
        } while (word);
      }
    }
  }

  // A word is the largest integer type convenient for bitwise operations.
  using word_t = uintptr_t;
  static constexpr size_t kBytesInWord = sizeof(word_t);
  static constexpr size_t kBitsInWord = CHAR_BIT * kBytesInWord;
  static constexpr size_t kSizeInWords = kSizeInBits / kBitsInWord;
  // All words are logically split into lines.
  // When `set()` is called, we set the corresponding element of `lines_` to 1,
  // so that we now know that at least 1 bit in that line is set. Then, in
  // `ForEachNonZeroBit()`, we iterate only those lines that have non-zero bits.
  static constexpr size_t kBytesInLine = 64 * 8;
  static constexpr size_t kWordsInLine = kBytesInLine / kBytesInWord;
  static constexpr size_t kSizeInLines = kSizeInWords / kWordsInLine;
  ConcurrentByteSet<kSizeInLines> lines_;
  // NOTE: No initializer for performance (`kSizeInWords` can be quite large).
  // Relies on static initialization in the process image (see the class
  // comment).
  word_t words_[kSizeInWords];
};

}  // namespace fuzztest::internal

#endif  // THIRD_PARTY_CENTIPEDE_CONCURRENT_BITSET_H_
