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

#include <cstdint>
#include <limits>

#include "gtest/gtest.h"
#include "absl/random/bit_gen_ref.h"
#include "absl/random/random.h"
#include "./fuzztest/fuzzing_bit_gen.h"

namespace fuzztest {
namespace {

const uint8_t kControlStream[6] = {
    0,  // data stream variate
    1,  // lcg variate
    2,  // min
    3,  // max
    4,  // mean
    5,  // alternate variate
};

const uint8_t kDataStream[40] = {
    1,    2,    3,    4,    5,    6,    7,  8,   //
    42,   42,   42,   42,   42,   42,   42, 42,  //
    50,   60,   70,   80,   10,   20,   30, 40,  //
    0x7f, 0x0f, 0x6f, 0x0f, 0x5f, 0x0f,
};
const uint64_t kSeedValue = 0x0807060504030201;

// Tests for the absl/random distribution functions which use the
// fuzztest::internal::RegisterAbslRandomFuzzingMocks() function.

TEST(FuzzingBitGenTest, BernoulliDistributionUsesMock) {
  FuzzingBitGen bitgen(kDataStream, kControlStream, kSeedValue);
  absl::BitGenRef ref(bitgen);

  EXPECT_TRUE(absl::Bernoulli(ref, 0.5));
  EXPECT_TRUE(absl::Bernoulli(ref, 0.5));   // lcg
  EXPECT_FALSE(absl::Bernoulli(ref, 0.5));  // min
  EXPECT_TRUE(absl::Bernoulli(ref, 0.5));   // max
  EXPECT_TRUE(absl::Bernoulli(ref, 0.6));   // mean
}

TEST(FuzzingBitGenTest, BetaDistributionUsesMock) {
  FuzzingBitGen bitgen(kDataStream, kControlStream, kSeedValue);
  absl::BitGenRef ref(bitgen);

  EXPECT_DOUBLE_EQ(absl::Beta<double>(ref, 2.0, 2.0), 0.081234075853663129);
  EXPECT_DOUBLE_EQ(absl::Beta<double>(ref, 2.0, 2.0),
                   0.65593732986573283);                     // lcg
  EXPECT_DOUBLE_EQ(absl::Beta<double>(ref, 2.0, 2.0), 0.0);  // min
  EXPECT_DOUBLE_EQ(absl::Beta<double>(ref, 2.0, 2.0), 1.0);  // max
  EXPECT_DOUBLE_EQ(absl::Beta<double>(ref, 2.0, 2.0), 0.5);  // mean
}

TEST(FuzzingBitGenTest, ExponentialDistributionUsesMock) {
  FuzzingBitGen bitgen(kDataStream, kControlStream, kSeedValue);
  absl::BitGenRef ref(bitgen);

  EXPECT_DOUBLE_EQ(absl::Exponential<double>(ref, 2.0), 0.015929665930210696);
  EXPECT_DOUBLE_EQ(absl::Exponential<double>(ref, 2.0),  // lcg
                   0.62503166008171429);
  EXPECT_DOUBLE_EQ(absl::Exponential<double>(ref, 2.0), 0.0);  // min
  EXPECT_DOUBLE_EQ(absl::Exponential<double>(ref, 2.0),        // max
                   std::numeric_limits<double>::max());
  EXPECT_DOUBLE_EQ(absl::Exponential<double>(ref, 2.0), 0.5);  // mean
  EXPECT_DOUBLE_EQ(absl::Exponential<double>(ref, 2.0),        // alt
                   2.9609063397732257e+307);
}

TEST(FuzzingBitGenTest, GaussianDistributionUsesMock) {
  FuzzingBitGen bitgen(kDataStream, kControlStream, kSeedValue);
  absl::BitGenRef ref(bitgen);

  EXPECT_DOUBLE_EQ(absl::Gaussian<double>(ref, 10.0, 1.0), 10.215901634330736);
  EXPECT_DOUBLE_EQ(absl::Gaussian<double>(ref, 10.0, 1.0),
                   9.3160235046777462);                     // lcg
  EXPECT_DOUBLE_EQ(absl::Gaussian<double>(ref, 10.0, 1.0),  // min
                   -std::numeric_limits<double>::max());
  EXPECT_DOUBLE_EQ(absl::Gaussian<double>(ref, 10.0, 1.0),  // max
                   std::numeric_limits<double>::max());
  EXPECT_DOUBLE_EQ(absl::Gaussian<double>(ref, 10.0, 1.0), 10.0);  // mean
  EXPECT_DOUBLE_EQ(absl::Gaussian<double>(ref, 10.0, 1.0),         // alt
                   3.2941176470588234);
}

TEST(FuzzingBitGenTest, LogUniformDistributionUsesMock) {
  FuzzingBitGen bitgen(kDataStream, kControlStream, kSeedValue);
  absl::BitGenRef ref(bitgen);

  EXPECT_EQ(absl::LogUniform<int>(ref, 10, 1000), 10);
  EXPECT_EQ(absl::LogUniform<int>(ref, 10, 1000), 11);    // lcg
  EXPECT_EQ(absl::LogUniform<int>(ref, 10, 1000), 10);    // min
  EXPECT_EQ(absl::LogUniform<int>(ref, 10, 1000), 1000);  // max
  EXPECT_EQ(absl::LogUniform<int>(ref, 10, 1000), 214);   // mean (approx)
  EXPECT_EQ(absl::LogUniform<int>(ref, 10, 1000), 894);   // alt
}

TEST(FuzzingBitGenTest, PoissonDistributionUsesMock) {
  FuzzingBitGen bitgen(kDataStream, kControlStream, kSeedValue);
  absl::BitGenRef ref(bitgen);

  EXPECT_EQ(absl::Poisson<int>(ref, 10.0), 2);
  EXPECT_EQ(absl::Poisson<int>(ref, 10.0), 9);           // lcg
  EXPECT_EQ(absl::Poisson<int>(ref, 10.0), 0);           // min
  EXPECT_EQ(absl::Poisson<int>(ref, 10.0), 2147483647);  // max
  EXPECT_EQ(absl::Poisson<int>(ref, 10.0), 10);          // mean
  EXPECT_EQ(absl::Poisson<int>(ref, 10.0), 0);           // alt
}

TEST(FuzzingBitGenTest, ZipfDistributionUsesMock) {
  FuzzingBitGen bitgen(kDataStream, kControlStream, kSeedValue);
  absl::BitGenRef ref(bitgen);

  EXPECT_EQ(absl::Zipf<int>(ref, 100, 2.0, 1.0), 15);
  EXPECT_EQ(absl::Zipf<int>(ref, 100, 2.0, 1.0), 0);    // lcg
  EXPECT_EQ(absl::Zipf<int>(ref, 100, 2.0, 1.0), 0);    // min
  EXPECT_EQ(absl::Zipf<int>(ref, 100, 2.0, 1.0), 100);  // max
  EXPECT_NE(absl::Zipf<int>(ref, 100, 2.0, 1.0), -1);   // (unused)
  EXPECT_EQ(absl::Zipf<int>(ref, 100, 2.0, 1.0), 50);   // alt
}

TEST(FuzzingBitGenTest, UniformDistributionUInt) {
  FuzzingBitGen bitgen(kDataStream, kControlStream, kSeedValue);
  absl::BitGenRef ref(bitgen);

  EXPECT_EQ(absl::Uniform<uint16_t>(ref), 0x0201);
  EXPECT_EQ(absl::Uniform<uint16_t>(ref), 34107);  // lcg
  EXPECT_EQ(absl::Uniform<uint16_t>(ref), 0);      // min
  EXPECT_EQ(absl::Uniform<uint16_t>(ref),
            std::numeric_limits<uint16_t>::max());  // max
  EXPECT_EQ(absl::Uniform<uint16_t>(ref),
            std::numeric_limits<uint16_t>::max() / 2);  // mean
}

TEST(FuzzingBitGenTest, UniformDistributionInt) {
  FuzzingBitGen bitgen(kDataStream, kControlStream, kSeedValue);
  absl::BitGenRef ref(bitgen);

  EXPECT_EQ(absl::Uniform<uint64_t>(ref, 0, 100), 3);
  EXPECT_EQ(absl::Uniform<uint64_t>(ref, 0, 100), 71);  // lcg
  EXPECT_EQ(absl::Uniform<uint64_t>(ref, 0, 100), 0);   // min
  EXPECT_EQ(absl::Uniform<uint64_t>(ref, 0, 100), 99);  // max
  EXPECT_EQ(absl::Uniform<uint64_t>(ref, 0, 100), 49);  // mean
}

TEST(FuzzingBitGenTest, UniformDistributionReal) {
  FuzzingBitGen bitgen(kDataStream, kControlStream, kSeedValue);
  absl::BitGenRef ref(bitgen);

  EXPECT_DOUBLE_EQ(absl::Uniform<double>(ref, 0.0, 100.0), 3.1357170319108034);
  EXPECT_DOUBLE_EQ(absl::Uniform<double>(ref, 0.0, 100.0),  // lcg
                   71.351334409602003);
  EXPECT_DOUBLE_EQ(absl::Uniform<double>(ref, 0.0, 100.0), 0.0);   // min
  EXPECT_LT(absl::Uniform<double>(ref, 0.0, 100.0), 100.0);        // max
  EXPECT_DOUBLE_EQ(absl::Uniform<double>(ref, 0.0, 100.0), 50.0);  // mean
}

}  // namespace
}  // namespace fuzztest
