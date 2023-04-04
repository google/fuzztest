#ifndef FUZZTEST_FUZZTEST_INTERNAL_BITMAP_H_
#define FUZZTEST_FUZZTEST_INTERNAL_BITMAP_H_

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>

#include "./fuzztest/internal/logging.h"

namespace fuzztest::internal {

// Branch hints.
#define unlikely(_expr) __builtin_expect((_expr), false)

inline size_t RoundUpToPowerOf2(size_t pow2, size_t value) {
  FUZZTEST_INTERNAL_CHECK_PRECONDITION(__builtin_popcountll(pow2) == 1,
                                       "Must be power of 2.");
  return (value + pow2 - 1) & ~(pow2 - 1);
}

// Insert-only thread/fiber-safe bitmap.
class Bitmap {
 public:
  explicit Bitmap(size_t length)
      : length_(length),
        bitmap_(new std::atomic<uint8_t>[RoundUpToPowerOf2(8, length) / 8]()) {}

  // Set appropriate bit in index. Use an atomic compare-and-swap loop.
  void Set(size_t index) {
    FUZZTEST_INTERNAL_CHECK_PRECONDITION(
        index < length_, "Index into bitmap must lie within range.");
    uint8_t mask = 1ull << (index % 8);
    std::atomic<uint8_t>& slot = bitmap_[index / 8];
    uint8_t value = slot.load();
    do {
      // Someone else concurrently or previously set our bit.
      if ((value & mask) != 0) {
        return;
      }
      // compare_exchange_weak swaps the new masked value if-and-only-if
      // the previous value remains unchanged. It returns false when value does
      // not match (and stores new value) and aborts update. This happens when
      // a bit in the slot is concurrently updated. Safe to retry. This will
      // always succeed eventually when no concurrent updates conflict.
    } while (unlikely(!slot.compare_exchange_weak(value, value | mask)));

    // This caller set the bit. Increment the total count.
    size_t result = bits_set_.fetch_add(1);
    FUZZTEST_INTERNAL_CHECK_PRECONDITION(
        result <= length_, "Overflow in bits set in bitmap. Unrecoverable.");
  }

  // Number of bits set.
  size_t AreSet() const { return bits_set_.load(); }

  // Number of bits unset.
  size_t AreUnset() const {
    size_t bits_set = AreSet();
    FUZZTEST_INTERNAL_CHECK_PRECONDITION(
        bits_set <= length_, "Overflow in bits set in bitmap. Unrecoverable.");
    return length_ - bits_set;
  }

 private:
  size_t length_;
  std::atomic<size_t> bits_set_{0};
  std::unique_ptr<std::atomic<uint8_t>[]> bitmap_;
};

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_BITMAP_H_
