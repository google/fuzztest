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

#include "./centipede/shared_memory_blob_sequence.h"

#include <unistd.h>

#include <cstdint>
#include <sstream>
#include <string>
#include <thread>  // NOLINT
#include <vector>

#include "gtest/gtest.h"
#include "./centipede/blob_sequence.h"

namespace centipede {
namespace {

std::string ShmemName() {
  std::ostringstream oss;
  oss << "/shared_memory_blob_sequence_test-" << getpid() << "-"
      << std::this_thread::get_id();
  return oss.str();
}

TEST(SharedMemoryBlobSequence, ParentChild) {
  std::vector<uint8_t> kTestData1 = {1, 2, 3};
  std::vector<uint8_t> kTestData2 = {4, 5, 6, 7};
  std::vector<uint8_t> kTestData3 = {8, 9};
  std::vector<uint8_t> kTestData4 = {'a', 'b', 'c', 'd', 'e'};

  // Creating a child w/o first creating a parent should crash.
  EXPECT_DEATH(
      SharedMemoryBlobSequence child_with_no_parent(ShmemName().c_str()),
      "shm_open\\(\\) failed");

  SharedMemoryBlobSequence parent_shmem(ShmemName().c_str(), 1000);
  BlobSequence& parent = parent_shmem.blob_seq();
  // Parent writes data.
  EXPECT_TRUE(parent.Write(Blob::EncodeBlobFromVec(kTestData1, 123)));
  EXPECT_TRUE(parent.Write(Blob::EncodeBlobFromVec(kTestData2, 456)));

  // Child created.
  SharedMemoryBlobSequence child_shmem(ShmemName().c_str());
  BlobSequence& child = child_shmem.blob_seq();
  // Child reads data.
  auto blob1 = child.Read();
  EXPECT_EQ(kTestData1, Blob::EncodeVecFromBlob(blob1));
  EXPECT_EQ(blob1.tag, 123);
  auto blob2 = child.Read();
  EXPECT_EQ(kTestData2, Blob::EncodeVecFromBlob(blob2));
  EXPECT_EQ(blob2.tag, 456);
  EXPECT_FALSE(child.Read().IsValid());

  // Child writes data.
  child.Reset();
  EXPECT_TRUE(child.Write(Blob::EncodeBlobFromVec(kTestData3)));
  EXPECT_TRUE(child.Write(Blob::EncodeBlobFromVec(kTestData4)));

  // Parent reads data.
  parent.Reset();
  EXPECT_EQ(kTestData3, Blob::EncodeVecFromBlob(parent.Read()));
  EXPECT_EQ(kTestData4, Blob::EncodeVecFromBlob(parent.Read()));
  EXPECT_FALSE(parent.Read().IsValid());
}

TEST(SharedMemoryBlobSequence, CheckForResourceLeaks) {
  const int kNumIters = 1 << 17;  // Some large number of iterations.
  const int kBlobSize = 1 << 30;  // Some large blob size.
  // Create and destroy lots of parent/child blob pairs.
  for (int iter = 0; iter < kNumIters; iter++) {
    SharedMemoryBlobSequence parent_shmem(ShmemName().c_str(), kBlobSize);
    BlobSequence& parent = parent_shmem.blob_seq();
    parent.Write(Blob::EncodeBlobFromVec({1, 2, 3}));
    SharedMemoryBlobSequence child_shmem(ShmemName().c_str());
    BlobSequence& child = child_shmem.blob_seq();
    EXPECT_EQ(child.Read().size, 3);
  }
  // Create a parent blob, then create and destroy lots of child blobs.
  SharedMemoryBlobSequence parent_shmem(ShmemName().c_str(), kBlobSize);
  BlobSequence& parent = parent_shmem.blob_seq();
  parent.Write(Blob::EncodeBlobFromVec({1, 2, 3, 4}));
  for (int iter = 0; iter < kNumIters; iter++) {
    SharedMemoryBlobSequence child_shmem(ShmemName().c_str());
    BlobSequence& child = child_shmem.blob_seq();
    EXPECT_EQ(child.Read().size, 4);
  }
}

// Test ReleaseSharedMemory and NumBytesUsed.
TEST(SharedMemoryBlobSequence, ReleaseSharedMemory) {
  // Allocate a blob sequence with 1M bytes of storage.
  SharedMemoryBlobSequence shmem_blobseq(ShmemName().c_str(), 1 << 20);
  BlobSequence& blobseq = shmem_blobseq.blob_seq();
  EXPECT_EQ(shmem_blobseq.NumBytesUsed(), 0);
  EXPECT_TRUE(blobseq.Write(Blob::EncodeBlobFromVec({1, 2, 3, 4})));
  EXPECT_GT(shmem_blobseq.NumBytesUsed(), 5);
  shmem_blobseq.ReleaseSharedMemory();
  EXPECT_EQ(shmem_blobseq.NumBytesUsed(), 0);
  EXPECT_TRUE(blobseq.Write(Blob::EncodeBlobFromVec({1, 2, 3, 4})));
  EXPECT_GT(shmem_blobseq.NumBytesUsed(), 5);
}

}  // namespace
}  // namespace centipede
