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

#ifndef THIRD_PARTY_CENTIPEDE_HASHED_RING_BUFFER_H_
#define THIRD_PARTY_CENTIPEDE_HASHED_RING_BUFFER_H_

#include <string.h>

// WARNING!!!: Be very careful with what STL headers or other dependencies you
// add here. This header needs to remain mostly bare-bones so that we can
// include it into runner.
#include <cstddef>
#include <cstdint>

#include "./centipede/rolling_hash.h"

namespace fuzztest::internal {

// Fixed-size ring buffer that maintains a 32-bit hash of its elements.
// Create objects of this type as zero-initialized globals or thread-locals.
// In a zero-initialized object all values and the hash are zero.
// `kSize` indicates the maximum possible size for the ring-buffer.
// The actual size is passed to Reset().
template <size_t kSize>
class HashedRingBuffer {
 public:
  // Adds `new_item` and returns the new hash of the entire collection.
  // Evicts an old item.
  // Returns the new hash.
  uint32_t push(size_t new_item) {
    size_t new_pos = last_added_pos_ + 1;
    if (new_pos >= size_) new_pos = 0;
    size_t evicted_item = buffer_[new_pos];
    buffer_[new_pos] = new_item;
    hash_.Update(new_item, evicted_item);
    last_added_pos_ = new_pos;
    return hash_.Hash();
  }

  // Returns the current hash.
  uint32_t hash() const { return hash_.Hash(); }

  // Resets the current state, sets the ring buffer size to `size_` (<= kSize).
  void Reset(size_t size) {
    memset(this, 0, sizeof(*this));
    if (size > kSize) __builtin_trap();  // can't use CHECK in the runner.
    size_ = size;
    hash_.Reset(size);
  }

 private:
  size_t buffer_[kSize];   // All elements.
  size_t last_added_pos_;  // Position of the last added element.
  size_t size_;            // Real size of the ring buffer, <= kSize.
  RollingHash hash_;
};

}  // namespace fuzztest::internal

#endif  // THIRD_PARTY_CENTIPEDE_HASHED_RING_BUFFER_H_
