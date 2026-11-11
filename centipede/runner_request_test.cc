// Copyright 2026 The Centipede Authors.
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

#include "./centipede/runner_request.h"

#include <cstddef>
#include <cstdint>
#include <vector>

#include "gtest/gtest.h"
#include "./centipede/shared_memory_blob_sequence.h"
#include "./common/defs.h"

namespace fuzztest::internal {
namespace {

ByteArray ToByteArray(Blob blob) {
  return ByteArray(blob.data, blob.data + blob.size);
}

TEST(RequestExecution, WithoutPersistentMetadataIsByteIdentical) {
  const ByteArray in0 = {10, 11};
  const ByteArray in1 = {20};
  const std::vector<ByteSpan> inputs = {in0, in1};

  std::vector<uint8_t> plain(512, 0);
  std::vector<uint8_t> no_metadata(512, 0);
  std::vector<uint8_t> all_empty_metadata(512, 0);
  BlobSequence plain_seq(plain.data(), plain.size());
  BlobSequence no_metadata_seq(no_metadata.data(), no_metadata.size());
  BlobSequence all_empty_metadata_seq(all_empty_metadata.data(),
                                      all_empty_metadata.size());

  ASSERT_EQ(RequestExecution(inputs, plain_seq), 2);
  ASSERT_EQ(
      RequestExecution(inputs, /*persistent_metadata=*/{}, no_metadata_seq), 2);
  ASSERT_EQ(RequestExecution(inputs, std::vector<ByteSpan>{{}, {}},
                             all_empty_metadata_seq),
            2);

  EXPECT_EQ(plain, no_metadata);
  EXPECT_EQ(plain, all_empty_metadata);
}

TEST(RequestExecution, WritesPersistentMetadataBeforeItsInput) {
  const ByteArray in0 = {10, 11};
  const ByteArray in1 = {20};
  const ByteArray in2 = {30, 31, 32};
  const ByteArray metadata0 = {1, 2};
  const ByteArray metadata2 = {3};
  const std::vector<ByteSpan> inputs = {in0, in1, in2};
  // Input 1 has no persistent metadata.
  const std::vector<ByteSpan> persistent_metadata = {metadata0, {}, metadata2};

  std::vector<uint8_t> buffer(1024, 0);
  BlobSequence blobseq(buffer.data(), buffer.size());
  ASSERT_EQ(RequestExecution(inputs, persistent_metadata, blobseq), 3);
  blobseq.Reset();

  EXPECT_TRUE(IsExecutionRequest(blobseq.Read()));
  size_t num_inputs = 0;
  ASSERT_TRUE(IsNumInputs(blobseq.Read(), num_inputs));
  EXPECT_EQ(num_inputs, 3);

  const Blob metadata0_blob = blobseq.Read();
  ASSERT_TRUE(IsPersistentMetadata(metadata0_blob));
  EXPECT_FALSE(IsDataInput(metadata0_blob));
  EXPECT_EQ(ToByteArray(metadata0_blob), metadata0);
  const Blob in0_blob = blobseq.Read();
  ASSERT_TRUE(IsDataInput(in0_blob));
  EXPECT_EQ(ToByteArray(in0_blob), in0);

  const Blob in1_blob = blobseq.Read();
  EXPECT_FALSE(IsPersistentMetadata(in1_blob));
  ASSERT_TRUE(IsDataInput(in1_blob));
  EXPECT_EQ(ToByteArray(in1_blob), in1);

  const Blob metadata2_blob = blobseq.Read();
  ASSERT_TRUE(IsPersistentMetadata(metadata2_blob));
  EXPECT_EQ(ToByteArray(metadata2_blob), metadata2);
  const Blob in2_blob = blobseq.Read();
  ASSERT_TRUE(IsDataInput(in2_blob));
  EXPECT_EQ(ToByteArray(in2_blob), in2);

  EXPECT_FALSE(blobseq.Read().IsValid());
}

TEST(RequestExecution, RejectsPersistentMetadataOfMismatchedSize) {
  const ByteArray in0 = {10, 11};
  const ByteArray in1 = {20};
  const ByteArray metadata0 = {1, 2};
  std::vector<uint8_t> buffer(512, 0);
  BlobSequence blobseq(buffer.data(), buffer.size());

  EXPECT_EQ(RequestExecution({in0, in1}, {metadata0}, blobseq), 0);
}

TEST(RequestExecution, DoesNotCountAnInputWhoseDataDoesNotFit) {
  const ByteArray in0 = {10, 11};
  const ByteArray metadata0 = {1, 2};
  // The size of a request with just the metadata and the input.
  const size_t request_size = [&] {
    std::vector<uint8_t> buffer(1024, 0);
    BlobSequence blobseq(buffer.data(), buffer.size());
    RequestExecution({in0}, {metadata0}, blobseq);
    return blobseq.offset();
  }();

  // One byte short: the metadata fits, but the input does not.
  std::vector<uint8_t> buffer(request_size - 1, 0);
  BlobSequence blobseq(buffer.data(), buffer.size());
  EXPECT_EQ(RequestExecution({in0}, {metadata0}, blobseq), 0);
}

}  // namespace
}  // namespace fuzztest::internal
