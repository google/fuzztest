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

#include "./centipede/execution_result.h"

#include <unistd.h>

#include <memory>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./centipede/feature.h"
#include "./centipede/shared_memory_blob_sequence.h"

namespace centipede {
namespace {

TEST(ExecutionResult, WriteThenRead) {
  auto buffer = std::make_unique<uint8_t[]>(1000);
  BlobSequence blobseq(buffer.get(), 1000);
  BatchResult batch_result;

  // Imitate execution of two inputs.
  FeatureVec v1{1, 2, 3};
  FeatureVec v2{5, 6, 7, 8};
  std::vector<uint8_t> cmp0{5, 6, 7};
  std::vector<uint8_t> cmp1{6, 7, 8};
  std::vector<uint8_t> cmp2{7, 8, 9};
  ExecutionResult::Stats stats1{.peak_rss_mb = 10};
  ExecutionResult::Stats stats2{.peak_rss_mb = 20};
  // First input.
  EXPECT_TRUE(BatchResult::WriteInputBegin(blobseq));
  EXPECT_TRUE(BatchResult::WriteOneFeatureVec(v1.data(), v1.size(), blobseq));
  // Write stats after features. The order should not matter.
  EXPECT_TRUE(BatchResult::WriteStats(stats1, blobseq));
  // Done.
  EXPECT_TRUE(BatchResult::WriteInputEnd(blobseq));

  // Second input.
  EXPECT_TRUE(BatchResult::WriteInputBegin(blobseq));
  // Write stats before features.
  EXPECT_TRUE(BatchResult::WriteStats(stats2, blobseq));
  EXPECT_TRUE(BatchResult::WriteOneFeatureVec(v2.data(), v2.size(), blobseq));
  // Write CMP traces.
  EXPECT_TRUE(BatchResult::WriteCmpArgs(cmp0.data(), cmp1.data(), cmp0.size(),
                                        blobseq));
  EXPECT_TRUE(BatchResult::WriteCmpArgs(cmp1.data(), cmp2.data(), cmp1.size(),
                                        blobseq));
  // Done.
  EXPECT_TRUE(BatchResult::WriteInputEnd(blobseq));

  // Ensure we've read them.
  blobseq.Reset();
  batch_result.ClearAndResize(2);
  EXPECT_TRUE(batch_result.Read(blobseq));
  EXPECT_EQ(batch_result.results().size(), 2);
  EXPECT_EQ(batch_result.results()[0].features(), v1);
  EXPECT_EQ(batch_result.results()[0].stats(), stats1);
  EXPECT_EQ(batch_result.results()[1].features(), v2);
  EXPECT_EQ(batch_result.results()[1].stats(), stats2);
  EXPECT_THAT(batch_result.results()[1].cmp_args(),
              testing::ElementsAre(3,        // size
                                   5, 6, 7,  // cmp0
                                   6, 7, 8,  // cmp1
                                   3,        // size
                                   6, 7, 8,  // cmp1
                                   7, 8, 9   // cmp2
                                   ));

  // If there are fewer ExecutionResult-s than expected everything should work.
  blobseq.Reset();
  batch_result.ClearAndResize(3);
  EXPECT_TRUE(batch_result.Read(blobseq));
  EXPECT_EQ(batch_result.results().size(), 3);
  EXPECT_EQ(batch_result.results()[0].features(), v1);
  EXPECT_EQ(batch_result.results()[1].features(), v2);
  EXPECT_EQ(batch_result.results()[2].features(), FeatureVec{});

  // If there are too many ExecutionResult-s, Read() should fail.
  // This should not happen in normal operation.
  blobseq.Reset();
  batch_result.ClearAndResize(1);
  EXPECT_FALSE(batch_result.Read(blobseq));
}
}  // namespace
}  // namespace centipede
