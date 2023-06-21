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
#include "./centipede/blob_sequence.h"

#include "gtest/gtest.h"

namespace centipede {
namespace testing {
namespace {

// Tests that Read-after-Write or Write-after-Read w/o Reset crashes.
TEST(BlobSequence, ReadVsWriteWithoutReset) {
  // Allocate a blob sequence with 1000 bytes of storage.
  std::vector<uint8_t> buffer(1000);
  BlobSequence blobseq{buffer.data(), buffer.size()};

  blobseq.Write(Blob::EncodeBlobFromVec({1, 2, 3}));
  EXPECT_DEATH(blobseq.Read(), "Had writes after reset");
  blobseq.Reset();
  EXPECT_EQ(blobseq.Read().size, 3);
  EXPECT_DEATH(blobseq.Write(Blob::EncodeBlobFromVec({1, 2, 3, 4})),
               "Had reads after reset");
  blobseq.Reset();
  blobseq.Write(Blob::EncodeBlobFromVec({1, 2, 3, 4}));
}

// Check cases when SharedMemoryBlobSequence is nearly full.
TEST(BlobSequence, WriteToFullSequence) {
  // Allocate a blob sequence with 28 bytes of storage.
  std::vector<uint8_t> buffer(28);
  BlobSequence blobseq{buffer.data(), buffer.size()};

  // 17 bytes: 8 bytes size, 8 bytes tag, 1 byte payload.
  EXPECT_TRUE(blobseq.Write(Blob::EncodeBlobFromVec({1})));
  blobseq.Reset();
  EXPECT_EQ(blobseq.Read().size, 1);
  EXPECT_FALSE(blobseq.Read().IsValid());

  // 20 bytes: 4-byte payload.
  blobseq.Reset();
  EXPECT_TRUE(blobseq.Write(Blob::EncodeBlobFromVec({1, 2, 3, 4})));
  blobseq.Reset();
  EXPECT_EQ(blobseq.Read().size, 4);
  EXPECT_FALSE(blobseq.Read().IsValid());

  // 23 bytes: 7-byte payload.
  blobseq.Reset();
  EXPECT_TRUE(blobseq.Write(Blob::EncodeBlobFromVec({1, 2, 3, 4, 5, 6, 7})));
  blobseq.Reset();
  EXPECT_EQ(blobseq.Read().size, 7);
  EXPECT_FALSE(blobseq.Read().IsValid());

  // 28 bytes: 12-byte payload.
  blobseq.Reset();
  EXPECT_TRUE(blobseq.Write(
      Blob::EncodeBlobFromVec({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12})));
  blobseq.Reset();
  EXPECT_EQ(blobseq.Read().size, 12);
  EXPECT_FALSE(blobseq.Read().IsValid());

  // 13-byte payload - there is not enough space (for 13+8 bytes).
  blobseq.Reset();
  EXPECT_FALSE(blobseq.Write(
      Blob::EncodeBlobFromVec({1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13})));
  blobseq.Reset();
  EXPECT_EQ(blobseq.Read().size, 12);  // State remained the same.

  // 1-, and 2- byte payloads. The last one fails.
  blobseq.Reset();
  EXPECT_TRUE(blobseq.Write(Blob::EncodeBlobFromVec({1})));
  EXPECT_FALSE(blobseq.Write(Blob::EncodeBlobFromVec({1, 2})));
  blobseq.Reset();
  EXPECT_EQ(blobseq.Read().size, 1);
  EXPECT_FALSE(blobseq.Read().IsValid());
}

// Test Write-Reset-Write-Read scenario.
TEST(BlobSequence, WriteAfterReset) {
  // Allocate a blob sequence with 100 bytes of storage.
  std::vector<uint8_t> buffer(100);
  BlobSequence blobseq{buffer.data(), buffer.size()};
  const std::vector<uint8_t> kFirstWriteData(/*count=*/64, /*value=*/255);
  EXPECT_TRUE(blobseq.Write(Blob::EncodeBlobFromVec(kFirstWriteData)));
  blobseq.Reset();  // The data in shmem is unchanged.
  const std::vector<uint8_t> kSecondWriteData{42, 43};
  EXPECT_TRUE(blobseq.Write(Blob::EncodeBlobFromVec(kSecondWriteData)));
  blobseq.Reset();  // The data in shmem is unchanged.
  auto blob1 = blobseq.Read();
  EXPECT_TRUE(blob1.IsValid());
  EXPECT_EQ(Blob::EncodeVecFromBlob(blob1), kSecondWriteData);
  auto blob2 = blobseq.Read();  // must be invalid.
  EXPECT_FALSE(blob2.IsValid());
}

}  // namespace
}  // namespace testing
}  // namespace centipede
