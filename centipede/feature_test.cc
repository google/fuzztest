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
#include "./centipede/logging.h"

namespace centipede {
namespace {

// Computes CMP features for all {a,b} pairs in `ab_vec`,
// verifies that all features are different.
static void TestCmpPairs(
    const std::vector<std::pair<uintptr_t, uintptr_t>> &ab_vec) {
  absl::flat_hash_set<feature_t> distinct_features;
  for (auto ab : ab_vec) {
    if (!distinct_features
             .insert(ConvertContextAndArgPairToNumber(ab.first, ab.second, 0))
             .second) {
      LOG(INFO) << ab.first << " " << ab.second;
    }
  }
  EXPECT_EQ(ab_vec.size(), distinct_features.size());
}

// Tests ConvertPcAndArgPairToCMPFeature.
// See comments for that function for details of what we are testing here.
TEST(Feature, ConvertPcAndArgPairToCMPFeature) {
  // Iterate though some huge number of different {a,b} pairs.
  // Verify that we have plenty of different features, but not *too many*.
  absl::flat_hash_set<feature_t> distinct_features;
  auto Inc = [](uintptr_t &a) {
    if (a < 1000)
      a++;
    else if (a < 1000000ULL)
      a += 123;
    else if (a < 1000000000ULL)
      a += 323456;
    else if (a < 1000000000000ULL)
      a += 423456789;
    else if (a < 1000000000000000ULL)
      a += 723456789012ULL;
    else
      a += (1ULL << 61) + 42;
  };

  uintptr_t kMax = 1ULL << 63;
  uintptr_t num_pairs_compared = 0;
  for (uintptr_t a = 0; a < kMax; Inc(a)) {
    for (uintptr_t b = 0; b < kMax; Inc(b)) {
      feature_t feature = ConvertContextAndArgPairToNumber(a, b, 0);
      distinct_features.insert(feature);
      num_pairs_compared++;
    }
  }
  LOG(INFO) << distinct_features.size() << " " << num_pairs_compared;
  EXPECT_GT(num_pairs_compared, 100000000);
  EXPECT_GT(distinct_features.size(), 1000);   // plenty.
  EXPECT_LT(distinct_features.size(), 20000);  // not too many.

  // Test a bunch of {a,b} pairs that represent the properties
  // that ConvertPcAndArgPairToCMPFeature tries to capture.
  TestCmpPairs({
      // a == b
      {50, 50},
      // diff
      {50, 49},
      {50, 48},
      {50, 47},
      {50, 40},
      {50, 30},
      {50, 20},
      {50, 51},
      {50, 52},
      {50, 53},
      {50, 60},
      {50, 70},
      {50, 80},
      // hamming
      {0x0000000000000000ULL, 0x0100000000000000ULL},
      {0x0000000000000000ULL, 0x0110000000000000ULL},
      {0x0000000000000000ULL, 0x0111000000000000ULL},
      {0x0000000000000000ULL, 0x0111100000000000ULL},
      {0x0000000000000000ULL, 0x0111110000000000ULL},
      {0x0000000000000000ULL, 0x0111111000000000ULL},
      {0x0000000000000000ULL, 0x0111111100000000ULL},
      {0x0000000000000000ULL, 0x0311111100000000ULL},
      {0x0000000000000000ULL, 0x0331111100000000ULL},
      {0x0000000000000000ULL, 0x0333111100000000ULL},
      {0x0000000000000000ULL, 0x0333311100000000ULL},
      {0x0000000000000000ULL, 0x0333331100000000ULL},
      {0x0000000000000000ULL, 0x0333333100000000ULL},
      {0x0000000000000000ULL, 0x0333333300000000ULL},
      {0x0000000000000000ULL, 0x7777777700000000ULL},
      {0x0000000000000000ULL, 0x77777777FFFFFFFFULL},
      // msb_eq
      {0x0000000000000000ULL, 0x0000000000000020ULL},
      {0x0000000000000000ULL, 0x0000000000000200ULL},
      {0x0000000000000000ULL, 0x0000000000002000ULL},
      {0x0000000000000000ULL, 0x0000000000020000ULL},
      {0x0000000000000000ULL, 0x0000000000200000ULL},
      {0x0000000000000000ULL, 0x0000000002000000ULL},
      {0x0000000000000000ULL, 0x0000000020000000ULL},
      {0x0000000000000000ULL, 0x0000000200000000ULL},
      {0x0000000000000000ULL, 0x0000002000000000ULL},
      {0x0000000000000000ULL, 0x0000020000000000ULL},
      {0x0000000000000000ULL, 0x0000200000000000ULL},
      {0x0000000000000000ULL, 0x0002000000000000ULL},
      {0x0000000000000000ULL, 0x0020000000000000ULL},
      {0x0000000000000000ULL, 0x0200000000000000ULL},
      {0x0000000000000000ULL, 0x2000000000000000ULL},
      // diff_log2.
      {0x0000000000000300ULL, 0x0000000000000400ULL},
      {0x0000000000003000ULL, 0x0000000000002000ULL},
      {0x0000000000030000ULL, 0x0000000000040000ULL},
      {0x0000000000300000ULL, 0x0000000000200000ULL},
      {0x0000000003000000ULL, 0x0000000004000000ULL},
      {0x0000000030000000ULL, 0x0000000020000000ULL},
      {0x0000000300000000ULL, 0x0000000400000000ULL},
      {0x0000003000000000ULL, 0x0000002000000000ULL},
      {0x0000030000000000ULL, 0x0000040000000000ULL},
      {0x0000300000000000ULL, 0x0000200000000000ULL},
      {0x0003000000000000ULL, 0x0004000000000000ULL},
      {0x0030000000000000ULL, 0x0020000000000000ULL},
      {0x0300000000000000ULL, 0x0400000000000000ULL},
      {0x3000000000000000ULL, 0x2000000000000000ULL},
  });

  // For some number of {a,b} pairs
  // test that different PCs generate different features.
  uintptr_t max_pc = 1000;
  for (uintptr_t a = 0; a < 10000; a += 123) {
    for (uintptr_t b = a; b < 20000; b += 321) {
      distinct_features.clear();
      num_pairs_compared = 0;
      for (uintptr_t pc = 0; pc < max_pc; pc++) {
        distinct_features.insert(ConvertContextAndArgPairToNumber(a, b, pc));
        num_pairs_compared++;
        EXPECT_EQ(distinct_features.size(), num_pairs_compared);
      }
    }
  }
}

template <typename Action>
void TrivialForEachNonZeroByte(uint8_t *bytes, size_t num_bytes,
                               Action action) {
  for (size_t i = 0; i < num_bytes; i++) {
    uint8_t value = bytes[i];
    if (value) {
      action(i, value);
      bytes[i] = 0;
    }
  }
}

TEST(Feature, ForEachNonZeroByte) {
  // Some long data with long spans of zeros and a few non-zeros.
  // We will test all sub-arrays of this array.
  const uint8_t test_data[] = {
      1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  };
  const size_t kTestDataSize = sizeof(test_data);
  uint8_t test_data_copy[kTestDataSize];

  for (size_t offset = 0; offset < kTestDataSize; offset++) {
    for (size_t size = 0; offset + size < kTestDataSize; size++) {
      std::vector<std::pair<size_t, uint8_t>> v1, v2;
      memcpy(test_data_copy, test_data, kTestDataSize);
      TrivialForEachNonZeroByte(
          test_data_copy + offset, size,
          [&](size_t idx, uint8_t value) { v1.emplace_back(idx, value); });
      for (size_t i = 0; i < size; ++i) {
        CHECK_EQ(test_data_copy[offset + i], 0);
      }

      memcpy(test_data_copy, test_data, kTestDataSize);
      ForEachNonZeroByte(
          test_data_copy + offset, size,
          [&](size_t idx, uint8_t value) { v2.emplace_back(idx, value); });
      for (size_t i = 0; i < size; ++i) {
        CHECK_EQ(test_data_copy[offset + i], 0);
      }

      EXPECT_EQ(v1, v2);
    }
  }
}

TEST(Feature, HashedRingBuffer) {
  HashedRingBuffer<32> rb16;  // used with ring_buffer_size == 16
  HashedRingBuffer<32> rb32;  // used with ring_buffer_size == 32
  rb16.clear();
  rb32.clear();
  absl::flat_hash_set<size_t> hashes16, hashes32;
  size_t kNumIter = 1000000;
  // push a large number of different numbers into rb, ensure that most of the
  // resulting hashes are different.
  for (size_t i = 0; i < kNumIter; i++) {
    hashes16.insert(rb16.push(i, 16));
    hashes32.insert(rb32.push(i, 32));
  }
  LOG(INFO) << VV(hashes32.size()) << " " << VV(hashes16.size());
  // We allow only very few collisions.
  EXPECT_GT(hashes16.size(), kNumIter - 5);
  EXPECT_GT(hashes32.size(), kNumIter - 5);

  // Try all permutations of {0, 1, 2, ... 9}, ensure we have at least half
  // this many different hashes.
  std::vector<size_t> numbers(10);
  std::iota(numbers.begin(), numbers.end(), 0);
  hashes32.clear();
  size_t num_permutations = 0;
  while (std::next_permutation(numbers.begin(), numbers.end())) {
    ++num_permutations;
    rb32.clear();
    for (const auto number : numbers) {
      rb32.push(number, 32);
    }
    hashes32.insert(rb32.hash());
  }
  LOG(INFO) << VV(num_permutations) << " " << VV(hashes32.size());
  CHECK_GT(hashes32.size(), num_permutations / 2);
}

TEST(Feature, ConcurrentBitSet) {
  constexpr size_t kSize = 1 << 16;
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
  static ConcurrentBitSet<(1 << 16)> bs(absl::kConstInit);
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
