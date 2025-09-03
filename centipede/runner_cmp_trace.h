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

#ifndef THIRD_PARTY_CENTIPEDE_RUNNER_CMP_TRACE_H_
#define THIRD_PARTY_CENTIPEDE_RUNNER_CMP_TRACE_H_

// Capturing arguments of CMP instructions, memcmp, and similar.
// WARNING: this code needs to have minimal dependencies.

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace fuzztest::internal {

// Captures up to `kNumItems` different CMP argument pairs.
// Every argument is `kFixedSize` bytes.
//
// If `kFixedSize` == 0, the argument size is variable.
// Only the first `kNumBytesPerValue` bytes of every argument are captured.
// This is used to capture arguments of memcmp() and similar.
//
// Every new captured pair may overwrite a pair stored previously.
//
// Outside of tests, objects of this class will be created in TLS, thus no CTOR.
template <uint8_t kFixedSize, size_t kNumItems>
class CmpTrace {
 public:
  // kMaxNumBytesPerValue does not depend on kFixedSize.
  static constexpr size_t kMaxNumBytesPerValue = 16;
  static constexpr size_t kNumBytesPerValue =
      kFixedSize ? kFixedSize : kMaxNumBytesPerValue;

  // No CTOR - objects will be created in TLS.

  // Clears `this`.
  void Clear() { memset(this, 0, sizeof(*this)); }

  // Captures one CMP argument pair, as two byte arrays, `size` bytes each.
  void Capture(uint8_t size, const uint8_t *value0, const uint8_t *value1) {
    if (size > kNumBytesPerValue) size = kNumBytesPerValue;
    // We choose a pseudo-random slot each time.
    // This way after capturing many pairs we end up with up to `kNumItems`
    // pairs which are typically, but not always, the most recent.
    rand_seed_ = rand_seed_ * 1103515245 + 12345;
    const size_t index = rand_seed_ % kNumItems;
    Item& item = items_[index];
    sizes_[index] = size;
    __builtin_memcpy(item.value0, value0, size);
    __builtin_memcpy(item.value1, value1, size);
  }

  // Captures one CMP argument pair, as two integers of kFixedSize bytes each.
  template <typename T>
  void Capture(T value0, T value1) {
    // If both values are small, ignore them as not very useful.
    if (value0 < 256 && value1 < 256) return;
    static_assert(sizeof(T) == kFixedSize);
    Capture(sizeof(T), reinterpret_cast<const uint8_t *>(&value0),
            reinterpret_cast<const uint8_t *>(&value1));
  }

  // Iterates non-zero CMP pairs.
  template <typename Callback>
  void ForEachNonZero(Callback callback) {
    for (size_t i = 0; i < kNumItems; ++i) {
      const auto size = sizes_[i];
      if (size == 0 || size > kNumBytesPerValue) continue;
      sizes_[i] = 0;
      callback(size, items_[i].value0, items_[i].value1);
    }
  }

 private:
  // One CMP argument pair.
  struct Item {
    uint8_t value0[kNumBytesPerValue];
    uint8_t value1[kNumBytesPerValue];
  };

  // Value sizes of argument pairs. zero-size indicates that the corresponding
  // entry is empty.
  //
  // Marked volatile because of the potential racing between the owning thread
  // and the main thread, which is tolerated gracefully.
  volatile uint8_t sizes_[kNumItems];
  // Values of argument pairs.
  Item items_[kNumItems];

  // Pseudo-random seed.
  size_t rand_seed_;
};

}  // namespace fuzztest::internal

#endif  // THIRD_PARTY_CENTIPEDE_RUNNER_CMP_TRACE_H_
