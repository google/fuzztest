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

#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./centipede/defs.h"

namespace centipede {
namespace {

using ::testing::IsEmpty;

testing::Matcher<std::vector<std::pair<ByteSpan, ByteSpan>>>
UnorderedElementsAre(
    const std::vector<std::pair<ByteArray, ByteArray>>& expected) {
  std::vector<testing::Matcher<std::pair<ByteSpan, ByteSpan>>> matchers;
  for (const auto& p : expected) {
    auto [v1, v2] = p;
    matchers.push_back(testing::Pair(testing::ElementsAreArray(v1),
                                     testing::ElementsAreArray(v2)));
  }
  return testing::UnorderedElementsAreArray(matchers);
}

TEST(ExecutionMetadata, ForEachCmpEntryEnumeratesEntriesInRawBytes) {
  ExecutionMetadata metadata{.cmp_data = {
                                 2,         // size
                                 1, 2,      // a
                                 3, 4,      // b
                                 0,         // zero-sized entry
                                 3,         // size
                                 5, 6, 7,   // a
                                 8, 9, 10,  // b
                             }};
  std::vector<std::pair<ByteSpan, ByteSpan>> enumeration_result;
  EXPECT_TRUE(metadata.ForEachCmpEntry(
      [&](ByteSpan a, ByteSpan b) { enumeration_result.emplace_back(a, b); }));
  EXPECT_THAT(enumeration_result,
              UnorderedElementsAre(
                  {{{1, 2}, {3, 4}}, {{}, {}}, {{5, 6, 7}, {8, 9, 10}}}));
}

TEST(ExecutionMetadata, ForEachCmpEntryHandlesEmptyCmpData) {
  auto noop_callback = [](ByteSpan, ByteSpan) {};
  EXPECT_TRUE(ExecutionMetadata{.cmp_data = {}}.ForEachCmpEntry(noop_callback));
}

TEST(ExecutionMetadata,
     ForEachCmpEntryReturnsFalseOnCmpDataWithNotEnoughBytes) {
  auto noop_callback = [](ByteSpan, ByteSpan) {};
  const auto bad_metadata_1 = ExecutionMetadata{.cmp_data = {3, 1, 2, 3}};
  EXPECT_FALSE(bad_metadata_1.ForEachCmpEntry(noop_callback));
  const auto bad_metadata_2 = ExecutionMetadata{.cmp_data = {3, 1, 2, 3, 4, 5}};
  EXPECT_FALSE(bad_metadata_2.ForEachCmpEntry(noop_callback));
}

TEST(ExecutionMetadata, ForEachCmpEntryEnumeratesEntriesFromAppendCmpEntry) {
  ExecutionMetadata metadata;
  ASSERT_TRUE(metadata.AppendCmpEntry(ByteSpan({1, 2}), ByteSpan({3, 4})));
  std::vector<std::pair<ByteSpan, ByteSpan>> enumeration_result;
  EXPECT_TRUE(metadata.ForEachCmpEntry(
      [&](ByteSpan a, ByteSpan b) { enumeration_result.emplace_back(a, b); }));
  EXPECT_THAT(enumeration_result, UnorderedElementsAre({
                                      {{1, 2}, {3, 4}},
                                  }));
}

TEST(ExecutionMetadata, AppendCmpEntryReturnsFalseAndSkipsOnBadArgs) {
  ExecutionMetadata metadata;
  // Sizes don't match.
  EXPECT_FALSE(metadata.AppendCmpEntry(ByteSpan({}), ByteSpan({1})));
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
  ASSERT_TRUE(metadata_in.AppendCmpEntry(ByteSpan({1, 2}), ByteSpan({3, 4})));
  SharedMemoryBlobSequence blobseq("test", /*size=*/1024,
                                   /*use_posix_shmem=*/false);
  EXPECT_TRUE(metadata_in.Write(/*tag=*/1, blobseq));
  blobseq.Reset();
  Blob blob = blobseq.Read();
  ExecutionMetadata metadata_out;
  metadata_out.Read(blob);
  std::vector<std::pair<ByteSpan, ByteSpan>> enumeration_result;
  EXPECT_TRUE(metadata_out.ForEachCmpEntry(
      [&](ByteSpan a, ByteSpan b) { enumeration_result.emplace_back(a, b); }));
  EXPECT_THAT(enumeration_result, UnorderedElementsAre({
                                      {{1, 2}, {3, 4}},
                                  }));
}

}  // namespace
}  // namespace centipede
