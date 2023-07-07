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

#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace centipede {
namespace {

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
              testing::UnorderedElementsAreArray(
                  std::vector<std::pair<ByteSpan, ByteSpan>>{
                      {{1, 2}, {3, 4}},
                      {{}, {}},
                      {{5, 6, 7}, {8, 9, 10}},
                  }));
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

}  // namespace
}  // namespace centipede
