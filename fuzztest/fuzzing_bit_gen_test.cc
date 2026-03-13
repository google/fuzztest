// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./fuzztest/fuzzing_bit_gen.h"

#include <cstdint>
#include <limits>

#include "gtest/gtest.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"

namespace fuzztest {
namespace {
constexpr uint8_t kDataStream[18] = {
    1, 2,  3, 4, 5, 6, 7, 8,  //
    9, 10,                    //
};
constexpr uint64_t kSeedValue = 0x0807060504030201;

TEST(FuzzingBitGenTest, OperatorReturnsBytesFromStream) {
  constexpr uint8_t kControlStream[1] = {};
  // {} -> uses data stream, reads up to 8 bytes.
  FuzzingBitGen bitgen(kDataStream, kControlStream, kSeedValue);
  EXPECT_EQ(bitgen(), 0x0807060504030201);
  EXPECT_EQ(bitgen(), 0x0A09);
  EXPECT_NE(bitgen(), 0x0807060504030201);  // Data stream is exhausted.
}

TEST(FuzzingBitGenTest, OperatorUsesPcgForEmptyStreams) {
  FuzzingBitGen bitgen({}, {}, kSeedValue);
  uint64_t v1 = bitgen();
  EXPECT_NE(v1, 0);
  uint64_t v2 = bitgen();
  EXPECT_NE(v2, 0);

  FuzzingBitGen bitgen2({}, {}, kSeedValue);
  EXPECT_EQ(bitgen2(), v1);
  EXPECT_EQ(bitgen2(), v2);
}

TEST(FuzzingBitGenTest, OperatorUsesPcgForEmptyStreamsUnseeded) {
  FuzzingBitGen bitgen({});
  uint64_t v1 = bitgen();
  EXPECT_NE(v1, 0);
  uint64_t v2 = bitgen();
  EXPECT_NE(v2, 0);

  FuzzingBitGen bitgen2({});
  EXPECT_EQ(bitgen2(), v1);
  EXPECT_EQ(bitgen2(), v2);
}

TEST(FuzzingBitGenTest, OperatorUsesControlStream) {
  constexpr uint8_t kControlStream[7] = {
      0,  // data stream variate
      1,  // lcg variate
      2,  // min
      3,  // max
      4,  // mean
      5,  // alternate variate
      0,  // data stream variate
  };
  FuzzingBitGen bitgen(kDataStream, kControlStream);
  EXPECT_EQ(bitgen(), 0x0807060504030201);
  EXPECT_NE(bitgen(), 0);
  EXPECT_EQ(bitgen(), 0);                                         // min
  EXPECT_EQ(bitgen(), std::numeric_limits<uint64_t>::max());      // max
  EXPECT_EQ(bitgen(), std::numeric_limits<uint64_t>::max() / 2);  // mean
  EXPECT_EQ(bitgen(), 0x0a09);                                    // alternate
  EXPECT_EQ(bitgen(), 0);
}

TEST(FuzzingBitGenTest, MockingIsRepeatable) {
  FuzzingBitGen bg1(kDataStream, {}, kSeedValue);
  absl::BitGenRef ref1(bg1);
  int v_a = absl::Uniform<int>(ref1, 0, 100);
  int v_b = absl::Uniform<int>(ref1, 0, 100);
  int v_c = absl::Uniform<int>(ref1, 0, 100);
  uint64_t v_d = ref1();

  FuzzingBitGen bg2(kDataStream, {}, kSeedValue);
  absl::BitGenRef ref2(bg2);
  EXPECT_EQ(absl::Uniform<int>(ref2, 0, 100), v_a);
  EXPECT_EQ(absl::Uniform<int>(ref2, 0, 100), v_b);
  EXPECT_EQ(absl::Uniform<int>(ref2, 0, 100), v_c);
  EXPECT_EQ(ref2(), v_d);
}

}  // namespace
}  // namespace fuzztest
