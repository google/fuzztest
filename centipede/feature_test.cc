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

#include "./centipede/feature.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <numeric>
#include <string>
#include <thread>  // NOLINT.
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "absl/base/const_init.h"
#include "absl/container/flat_hash_set.h"
#include "./centipede/concurrent_byteset.h"
#include "./centipede/hashed_ring_buffer.h"
#include "./centipede/logging.h"

namespace centipede {
namespace {

TEST(Feature, HashedRingBuffer) {
  HashedRingBuffer<32> rb16;  // used with ring_buffer_size == 16
  HashedRingBuffer<32> rb32;  // used with ring_buffer_size == 32
  rb16.Reset(16);
  rb32.Reset(32);
  absl::flat_hash_set<size_t> hashes16, hashes32;
  size_t kNumIter = 10000000;
  // push a large number of different numbers into rb, ensure that most of the
  // resulting hashes are different.
  for (size_t i = 0; i < kNumIter; i++) {
    hashes16.insert(rb16.push(i));
    hashes32.insert(rb32.push(i));
  }
  LOG(INFO) << VV(hashes32.size()) << " " << VV(hashes16.size());
  // No collisions.
  EXPECT_EQ(hashes16.size(), kNumIter);
  EXPECT_EQ(hashes32.size(), kNumIter);

  // Try all permutations of {0, 1, 2, ... 9}, ensure we have at least half
  // this many different hashes.
  std::vector<size_t> numbers(10);
  std::iota(numbers.begin(), numbers.end(), 0);
  hashes32.clear();
  size_t num_permutations = 0;
  while (std::next_permutation(numbers.begin(), numbers.end())) {
    ++num_permutations;
    rb32.Reset(32);
    for (const auto number : numbers) {
      rb32.push(number);
    }
    hashes32.insert(rb32.hash());
  }
  LOG(INFO) << VV(num_permutations) << " " << VV(hashes32.size());
  CHECK_GT(hashes32.size(), num_permutations / 2);
}

TEST(Feature, ConcurrentBitSet) {
  constexpr size_t kSize = 1 << 18;
  static ConcurrentBitSet<kSize> bs(absl::kConstInit);
  std::vector<size_t> in_bits = {0, 1, 2, 100, 102, 1000000};
  std::vector<size_t> expected_out_bits = {0, 1, 2, 100, 102, 1000000 % kSize};
  std::vector<size_t> out_bits;
  for (auto idx : in_bits) {
    bs.set(idx);
  }
  bs.ForEachNonZeroBit([&](size_t idx) { out_bits.push_back(idx); });
  EXPECT_EQ(out_bits, expected_out_bits);

  bs.clear();
  out_bits.clear();
  bs.ForEachNonZeroBit([&](size_t idx) { out_bits.push_back(idx); });
  EXPECT_TRUE(out_bits.empty());
  bs.set(42);
  bs.ForEachNonZeroBit([&](size_t idx) { out_bits.push_back(idx); });
  expected_out_bits = {42};
  EXPECT_EQ(out_bits, expected_out_bits);
  // Check that all bits are now clear.
  out_bits.clear();
  bs.ForEachNonZeroBit([&](size_t idx) { out_bits.push_back(idx); });
  EXPECT_TRUE(out_bits.empty());
}

TEST(Feature, ConcurrentByteSet) {
  static ConcurrentByteSet<1024> bs(absl::kConstInit);
  const std::vector<std::pair<size_t, uint8_t>> in = {
      {0, 1}, {1, 42}, {2, 33}, {100, 15}, {102, 1}, {800, 66}};

  for (const auto &idx_value : in) {
    bs.Set(idx_value.first, idx_value.second);
  }

  // Test ForEachNonZeroByte.
  std::vector<std::pair<size_t, uint8_t>> out;
  bs.ForEachNonZeroByte(
      [&](size_t idx, uint8_t value) { out.emplace_back(idx, value); });
  EXPECT_EQ(out, in);

  // Now bs should be empty.
  out.clear();
  bs.ForEachNonZeroByte(
      [&](size_t idx, uint8_t value) { out.emplace_back(idx, value); });
  EXPECT_TRUE(out.empty());

  // Test SaturatedIncrement.
  for (const auto &idx_value : in) {
    for (auto iter = 0; iter < idx_value.second; ++iter) {
      bs.SaturatedIncrement(idx_value.first);
    }
  }
  bs.ForEachNonZeroByte(
      [&](size_t idx, uint8_t value) { out.emplace_back(idx, value); });
  EXPECT_EQ(out, in);
}

// Test a thread_local object.
static thread_local TwoLayerConcurrentByteSet<(1 << 17)> two_layer_byte_set(
    absl::kConstInit);

TEST(Feature, TwoLayerConcurrentByteSet) {
  auto &bs = two_layer_byte_set;
  const std::vector<std::pair<size_t, uint8_t>> in = {
      {0, 1}, {1, 42}, {2, 33}, {100, 15}, {102, 1}, {800, 66}};

  for (const auto &idx_value : in) {
    bs.Set(idx_value.first, idx_value.second);
  }

  // Test ForEachNonZeroByte.
  std::vector<std::pair<size_t, uint8_t>> out;
  bs.ForEachNonZeroByte(
      [&](size_t idx, uint8_t value) { out.emplace_back(idx, value); });
  EXPECT_EQ(out, in);

  // Now bs should be empty.
  out.clear();
  bs.ForEachNonZeroByte(
      [&](size_t idx, uint8_t value) { out.emplace_back(idx, value); });
  EXPECT_TRUE(out.empty());

  // Test SaturatedIncrement.
  for (const auto &idx_value : in) {
    for (auto iter = 0; iter < idx_value.second; ++iter) {
      bs.SaturatedIncrement(idx_value.first);
    }
  }
  bs.ForEachNonZeroByte(
      [&](size_t idx, uint8_t value) { out.emplace_back(idx, value); });
  EXPECT_EQ(out, in);
}

// Tests ConcurrentBitSet from multiple threads.
TEST(Feature, ConcurrentBitSet_Threads) {
  static ConcurrentBitSet<(1 << 18)> bs(absl::kConstInit);
  // 3 threads will each set one specific bit in a long loop.
  // 4th thread will set another bit, just once.
  // The set() function is lossy, i.e. it may fail to set the bit.
  // If the value is set in a long loop, it will be set with a probability
  // indistinguishable from one (at least this is my theory :).
  // But the 4th thread that sets its bit once, may actually fail to do it.
  // So, this test allows two outcomes (possible_bits3/possible_bits4).
  auto cb = [&](size_t idx) {
    for (size_t i = 0; i < 10000000; i++) {
      bs.set(idx);
    }
  };
  std::thread t1(cb, 10);
  std::thread t2(cb, 11);
  std::thread t3(cb, 14);
  std::thread t4([&]() { bs.set(15); });
  t1.join();
  t2.join();
  t3.join();
  t4.join();
  std::vector<size_t> bits;
  std::vector<size_t> possible_bits3 = {10, 11, 14};
  std::vector<size_t> possible_bits4 = {10, 11, 14, 15};
  bs.ForEachNonZeroBit([&](size_t idx) { bits.push_back(idx); });
  if (bits.size() == 3) {
    EXPECT_EQ(bits, possible_bits3);
  } else {
    EXPECT_EQ(bits, possible_bits4);
  }
}

// Tests TwoLayerConcurrentByteSet from multiple threads.
TEST(Feature, TwoLayerConcurrentByteSet_Threads) {
  static TwoLayerConcurrentByteSet<(1 << 16)> bs(absl::kConstInit);
  // 3 threads will each increment one specific byte in a long loop.
  // 4th thread will increment another byte, just once.
  auto cb = [&](size_t idx) {
    for (size_t i = 0; i < 10000000; i++) {
      bs.SaturatedIncrement(idx);
    }
  };
  std::thread t1(cb, 10);
  std::thread t2(cb, 11);
  std::thread t3(cb, 14);
  std::thread t4([&]() { bs.SaturatedIncrement(15); });
  t1.join();
  t2.join();
  t3.join();
  t4.join();
  const std::vector<std::pair<size_t, uint8_t>> expected = {
      {10, 255}, {11, 255}, {14, 255}, {15, 1}};
  std::vector<std::pair<size_t, uint8_t>> out;
  bs.ForEachNonZeroByte(
      [&](size_t idx, uint8_t value) { out.emplace_back(idx, value); });
  EXPECT_EQ(out, expected);
}

// Global ConcurrentBitSet with a absl::kConstInit CTOR.
static ConcurrentBitSet<(1 << 20)> large_concurrent_bitset(absl::kConstInit);
// Test a thread-local object.
static thread_local ConcurrentBitSet<(1 << 20)> large_tls_concurrent_bitset(
    absl::kConstInit);

TEST(Feature, ConcurrentBitSet_Large) {
  for (auto *bs : {&large_concurrent_bitset, &large_tls_concurrent_bitset}) {
    const std::vector<size_t> in_bits = {0,   1,     2,     100,   102,
                                         800, 10000, 20000, 30000, 500000};

    for (size_t iter = 0; iter < 100000; ++iter) {
      for (auto idx : in_bits) {
        bs->set(idx);
      }
      std::vector<size_t> out_bits;
      bs->ForEachNonZeroBit([&](size_t idx) { out_bits.push_back(idx); });
      EXPECT_EQ(out_bits, in_bits);
    }
  }
}

TEST(Feature, FeatureArray) {
  FeatureArray<3> array;
  EXPECT_EQ(array.size(), 0);
  array.push_back(10);
  EXPECT_EQ(array.size(), 1);
  array.push_back(20);
  EXPECT_EQ(array.size(), 2);
  array.clear();
  EXPECT_EQ(array.size(), 0);
  array.push_back(10);
  array.push_back(20);
  array.push_back(30);
  EXPECT_EQ(array.size(), 3);
  array.push_back(40);  // no space left.
  EXPECT_EQ(array.size(), 3);
  EXPECT_EQ(array.data()[0], 10);
  EXPECT_EQ(array.data()[1], 20);
  EXPECT_EQ(array.data()[2], 30);
}

TEST(Feature, Hash64Bits) {
  // Run a large sample of small integers and verify that lower X bits
  // of Hash64Bits(), for X in 64, 48, 32, and 20, are unique.
  absl::flat_hash_set<uint64_t> set64;
  absl::flat_hash_set<uint64_t> set48;
  absl::flat_hash_set<uint64_t> set32;
  absl::flat_hash_set<uint64_t> set20;
  size_t num_values = 0;
  constexpr uint64_t kMaxIntToCheck = 1ULL << 28;
  constexpr uint64_t kMask48 = (1ULL << 48) - 1;
  constexpr uint64_t kMask32 = (1ULL << 32) - 1;
  constexpr uint64_t kMask20 = (1ULL << 20) - 1;
  for (uint64_t i = 0; i < kMaxIntToCheck; i += 101, ++num_values) {
    set64.insert(Hash64Bits(i));
    set48.insert(Hash64Bits(i) & kMask48);
    set32.insert(Hash64Bits(i) & kMask32);
    set20.insert(Hash64Bits(i) & kMask20);
  }
  EXPECT_EQ(set64.size(), num_values);
  EXPECT_EQ(set48.size(), num_values);
  EXPECT_EQ(set32.size(), num_values);
  EXPECT_EQ(set20.size(), 1 << 20);  // all possible 20-bit numbers.

  // For a large number of pairs of small integers {i, j} verify that
  // values of Hash64Bits(i) ^ (j) are unique.
  set64.clear();
  num_values = 0;
  for (uint64_t i = 0; i < kMaxIntToCheck; i += 100000) {
    for (uint64_t j = 1; j < kMaxIntToCheck; j += 100000) {
      set64.insert(Hash64Bits(i) ^ (j));
      ++num_values;
    }
  }
  EXPECT_EQ(set64.size(), num_values);
}

}  // namespace
}  // namespace centipede
