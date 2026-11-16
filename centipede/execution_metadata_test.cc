// Copyright 2023 The Centipede Authors.
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

#include "./centipede/execution_metadata.h"

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/types/span.h"
#include "./centipede/runner_request.h"
#include "./centipede/shared_memory_blob_sequence.h"
#include "./common/defs.h"

namespace fuzztest::internal {
namespace {

using ::testing::IsEmpty;
using ::testing::UnorderedElementsAreArray;

TEST(ExecutionMetadata, ForEachCmpEntryEnumeratesEntriesInRawBytes) {
  ExecutionMetadata metadata;
  metadata.cmp_data = {
      2,         // size
      1, 2,      // a
      3, 4,      // b
      0,         // zero-sized entry
      3,         // size
      5, 6, 7,   // a
      8, 9, 10,  // b
  };
  std::vector<std::pair<ByteSpan, ByteSpan>> enumeration_result;
  EXPECT_TRUE(metadata.ForEachCmpEntry(
      [&](ByteSpan a, ByteSpan b) { enumeration_result.emplace_back(a, b); }));

  EXPECT_THAT(
      enumeration_result,
      UnorderedElementsAreArray(std::vector<std::pair<ByteSpan, ByteSpan>>{
          {{1, 2}, {3, 4}},
          {{}, {}},
          {{5, 6, 7}, {8, 9, 10}},
      }));
}

TEST(ExecutionMetadata, ForEachCmpEntryHandlesEmptyCmpData) {
  auto noop_callback = [](ByteSpan, ByteSpan) {};
  EXPECT_TRUE(ExecutionMetadata{}.ForEachCmpEntry(noop_callback));
}

TEST(ExecutionMetadata,
     ForEachCmpEntryReturnsFalseOnCmpDataWithNotEnoughBytes) {
  auto noop_callback = [](ByteSpan, ByteSpan) {};
  auto bad_metadata_1 = ExecutionMetadata{};
  bad_metadata_1.cmp_data = {3, 1, 2, 3};
  EXPECT_FALSE(bad_metadata_1.ForEachCmpEntry(noop_callback));
  auto bad_metadata_2 = ExecutionMetadata{};
  bad_metadata_2.cmp_data = {3, 1, 2, 3, 4, 5};
  EXPECT_FALSE(bad_metadata_2.ForEachCmpEntry(noop_callback));
}

TEST(ExecutionMetadata, ForEachCmpEntryEnumeratesEntriesFromAppendCmpEntry) {
  ExecutionMetadata metadata;
  ASSERT_TRUE(metadata.AppendCmpEntry({1, 2}, {3, 4}));
  std::vector<std::pair<ByteSpan, ByteSpan>> enumeration_result;
  EXPECT_TRUE(metadata.ForEachCmpEntry(
      [&](ByteSpan a, ByteSpan b) { enumeration_result.emplace_back(a, b); }));
  EXPECT_THAT(
      enumeration_result,
      UnorderedElementsAreArray(std::vector<std::pair<ByteSpan, ByteSpan>>{
          {{1, 2}, {3, 4}},
      }));
}

TEST(ExecutionMetadata, AppendCmpEntryReturnsFalseAndSkipsOnBadArgs) {
  ExecutionMetadata metadata;
  // Sizes don't match.
  EXPECT_FALSE(metadata.AppendCmpEntry({}, {1}));
  ByteArray long_byte_array;
  long_byte_array.resize(256);
  // Args too long.
  EXPECT_FALSE(metadata.AppendCmpEntry(long_byte_array, long_byte_array));
  // Should leave no entries and keep metadata well-formed.
  std::vector<std::pair<ByteSpan, ByteSpan>> enumeration_result;
  EXPECT_TRUE(metadata.ForEachCmpEntry(
      [&](ByteSpan a, ByteSpan b) { enumeration_result.emplace_back(a, b); }));
  EXPECT_THAT(enumeration_result, IsEmpty());
}

TEST(ExecutionMetadata, ReadAndWriteKeepsCmpEntries) {
  ExecutionMetadata metadata_in;
  ASSERT_TRUE(metadata_in.AppendCmpEntry({1, 2}, {3, 4}));
  std::vector<uint8_t> blob_storage;
  blob_storage.resize(1024);
  BlobSequence blobseq(blob_storage.data(), blob_storage.size());
  EXPECT_TRUE(metadata_in.Write(/*tag=*/1, blobseq));
  blobseq.Reset();
  Blob blob = blobseq.Read();
  ExecutionMetadata metadata_out;
  metadata_out.Read(blob);
  std::vector<std::pair<ByteSpan, ByteSpan>> enumeration_result;
  EXPECT_TRUE(metadata_out.ForEachCmpEntry(
      [&](ByteSpan a, ByteSpan b) { enumeration_result.emplace_back(a, b); }));
  EXPECT_THAT(
      enumeration_result,
      UnorderedElementsAreArray(std::vector<std::pair<ByteSpan, ByteSpan>>{
          {{1, 2}, {3, 4}},
      }));
}

TEST(DiffEnvelope, RoundTripsEveryKindAndEmptyCmp) {
  const ByteArray payload = {'p', 0, 'q'};
  for (const ByteArray& cmp : std::vector<ByteArray>{{2, 1, 2, 3, 4}, {}}) {
    for (const auto& [kind, kind_payload] :
         std::vector<std::pair<DiffEnvelopeKind, ByteArray>>{
             {DiffEnvelopeKind::kExpectations, payload},
             {DiffEnvelopeKind::kRecords, payload},
             {DiffEnvelopeKind::kRecords, {}},
             {DiffEnvelopeKind::kAck, {}},
             {DiffEnvelopeKind::kSkippedUnparsable, {}},
         }) {
      SCOPED_TRACE(static_cast<int>(kind));
      const ByteArray envelope = EncodeDiffEnvelope(kind, cmp, kind_payload);
      DiffEnvelopeKind decoded_kind;
      ByteSpan decoded_cmp;
      ByteSpan decoded_payload;
      ASSERT_TRUE(DecodeDiffEnvelope(envelope, decoded_kind, decoded_cmp,
                                     decoded_payload));
      EXPECT_EQ(decoded_kind, kind);
      EXPECT_EQ(ByteArray(decoded_cmp.begin(), decoded_cmp.end()), cmp);
      EXPECT_EQ(ByteArray(decoded_payload.begin(), decoded_payload.end()),
                kind_payload);
    }
  }
}

TEST(DiffEnvelope, HasThePinnedLayout) {
  const ByteArray envelope =
      EncodeDiffEnvelope(DiffEnvelopeKind::kRecords, {9}, {7, 8});
  const ByteArray expected = {
      'F', 'T', 'D', 'I', 'F', 'F', '0', '1',  // magic
      1,                                       // kind
      1,   0,   0,   0,   0,   0,   0,   0,    // cmp_size (LE)
      9,                                       // cmp
      2,   0,   0,   0,   0,   0,   0,   0,    // diff_size (LE)
      7,   8};                                 // payload
  EXPECT_EQ(envelope, expected);
}

TEST(DiffEnvelope, RejectsMalformedEnvelopesAndLeavesOutputsUntouched) {
  const ByteArray good =
      EncodeDiffEnvelope(DiffEnvelopeKind::kExpectations, {1, 2}, {3});
  std::vector<ByteArray> bad_envelopes;
  // Wrong magic.
  bad_envelopes.push_back(good);
  bad_envelopes.back()[0] = 'X';
  // Unknown kind.
  bad_envelopes.push_back(good);
  bad_envelopes.back()[8] = 4;
  // Non-empty payload for kAck and kSkippedUnparsable.
  bad_envelopes.push_back(EncodeDiffEnvelope(DiffEnvelopeKind::kAck, {}, {1}));
  bad_envelopes.push_back(
      EncodeDiffEnvelope(DiffEnvelopeKind::kSkippedUnparsable, {}, {1}));
  // Truncations at every length.
  for (size_t size = 0; size < good.size(); ++size) {
    bad_envelopes.push_back(ByteArray(good.begin(), good.begin() + size));
  }
  // Trailing bytes.
  bad_envelopes.push_back(good);
  bad_envelopes.back().push_back(0);
  // Huge cmp_size.
  ByteArray huge_cmp = good;
  for (size_t i = 9; i < 17; ++i) huge_cmp[i] = 0xff;
  bad_envelopes.push_back(huge_cmp);
  // 64-bit wrap-around on cmp_size: 17 + cmp_size wraps modulo 2^64.
  ByteArray wrap_cmp = good;
  const uint64_t wrap_cmp_val = ~uint64_t{0} - 16;
  for (size_t i = 0; i < 8; ++i) {
    wrap_cmp[9 + i] = static_cast<uint8_t>((wrap_cmp_val >> (8 * i)) & 0xff);
  }
  bad_envelopes.push_back(wrap_cmp);
  // Huge diff_size (valid cmp_size = 2, diff_size = UINT64_MAX).
  ByteArray huge_diff = good;
  for (size_t i = 19; i < 27; ++i) huge_diff[i] = 0xff;
  bad_envelopes.push_back(huge_diff);
  // 64-bit wrap-around: cmp_size = 2, diff_size = UINT64_MAX - 26 so that
  // header + cmp_size + diff_size wraps modulo 2^64.
  ByteArray wrap_diff = good;
  const uint64_t wrap_val = ~uint64_t{0} - 26;
  for (size_t i = 0; i < 8; ++i) {
    wrap_diff[19 + i] = static_cast<uint8_t>((wrap_val >> (8 * i)) & 0xff);
  }
  bad_envelopes.push_back(wrap_diff);
  // Raw CMP data (no envelope).
  bad_envelopes.push_back({2, 1, 2, 3, 4});

  for (size_t idx = 0; idx < bad_envelopes.size(); ++idx) {
    SCOPED_TRACE(idx);
    const ByteArray& bad = bad_envelopes[idx];
    DiffEnvelopeKind kind = DiffEnvelopeKind::kAck;
    const ByteArray sentinel = {42};
    ByteSpan cmp = sentinel;
    ByteSpan payload = sentinel;
    EXPECT_FALSE(DecodeDiffEnvelope(bad, kind, cmp, payload));
    EXPECT_EQ(kind, DiffEnvelopeKind::kAck);
    EXPECT_EQ(cmp.data(), sentinel.data());
    EXPECT_EQ(payload.data(), sentinel.data());
  }
}

TEST(RunnerRequest, RequestExecutionWithOptionalMetadataInterleavesCleanly) {
  const ByteArray in0 = {10, 11};
  const ByteArray in1 = {20};
  const ByteArray in2 = {30, 31, 32};
  const ByteArray meta0 =
      EncodeDiffEnvelope(DiffEnvelopeKind::kExpectations, {}, {1, 2});
  const ByteArray meta1 = {};  // Omitted metadata blob.
  const ByteArray meta2 =
      EncodeDiffEnvelope(DiffEnvelopeKind::kExpectations, {}, {3});

  // All-empty metadata is byte-identical to the 2-argument RequestExecution.
  std::vector<uint8_t> plain_buf(512, 0);
  std::vector<uint8_t> empty_meta_buf(512, 0);
  BlobSequence plain_seq(plain_buf.data(), plain_buf.size());
  BlobSequence empty_meta_seq(empty_meta_buf.data(), empty_meta_buf.size());
  const std::vector<ByteSpan> inputs = {in0, in1, in2};
  const std::vector<ByteSpan> all_empty = {{}, {}, {}};
  ASSERT_EQ(RequestExecution(inputs, plain_seq), 3);
  ASSERT_EQ(RequestExecution(inputs, all_empty, empty_meta_seq), 3);
  EXPECT_EQ(plain_seq.offset(), empty_meta_seq.offset());
  EXPECT_EQ(plain_buf, empty_meta_buf);

  // Mismatched metadata size returns 0.
  std::vector<uint8_t> bad_buf(512, 0);
  BlobSequence bad_seq(bad_buf.data(), bad_buf.size());
  EXPECT_EQ(RequestExecution(inputs, {meta0}, bad_seq), 0);

  // Mixed non-empty / empty metadata writes metadata only before in0 and in2.
  std::vector<uint8_t> mixed_buf(1024, 0);
  BlobSequence mixed_seq(mixed_buf.data(), mixed_buf.size());
  ASSERT_EQ(RequestExecution(inputs, {meta0, meta1, meta2}, mixed_seq), 3);
  mixed_seq.Reset();

  EXPECT_TRUE(IsExecutionRequest(mixed_seq.Read()));
  size_t num_inputs = 0;
  ASSERT_TRUE(IsNumInputs(mixed_seq.Read(), num_inputs));
  EXPECT_EQ(num_inputs, 3);

  ExecutionMetadata parsed_meta0;
  const Blob meta0_blob = mixed_seq.Read();
  ASSERT_TRUE(IsExecutionMetadata(meta0_blob, parsed_meta0));
  EXPECT_EQ(parsed_meta0.cmp_data, meta0);
  const Blob in0_blob = mixed_seq.Read();
  ASSERT_TRUE(IsDataInput(in0_blob));
  EXPECT_EQ(ByteArray(in0_blob.data, in0_blob.data + in0_blob.size), in0);

  // Input 1 has no preceding metadata blob.
  const Blob in1_blob = mixed_seq.Read();
  ExecutionMetadata unused_meta;
  EXPECT_FALSE(IsExecutionMetadata(in1_blob, unused_meta));
  ASSERT_TRUE(IsDataInput(in1_blob));
  EXPECT_EQ(ByteArray(in1_blob.data, in1_blob.data + in1_blob.size), in1);

  ExecutionMetadata parsed_meta2;
  const Blob meta2_blob = mixed_seq.Read();
  ASSERT_TRUE(IsExecutionMetadata(meta2_blob, parsed_meta2));
  EXPECT_EQ(parsed_meta2.cmp_data, meta2);
  const Blob in2_blob = mixed_seq.Read();
  ASSERT_TRUE(IsDataInput(in2_blob));
  EXPECT_EQ(ByteArray(in2_blob.data, in2_blob.data + in2_blob.size), in2);

  // If the buffer overflows mid-pair (fits meta0, fails on in0), returns 0.
  const size_t exact_two_blobs = [&] {
    std::vector<uint8_t> tmp(1024, 0);
    BlobSequence seq(tmp.data(), tmp.size());
    RequestExecution({in0}, {meta0}, seq);
    return seq.offset();
  }();
  std::vector<uint8_t> tight_buf(exact_two_blobs - 1, 0);
  BlobSequence tight_seq(tight_buf.data(), tight_buf.size());
  EXPECT_EQ(RequestExecution({in0}, {meta0}, tight_seq), 0);
}

}  // namespace
}  // namespace fuzztest::internal
