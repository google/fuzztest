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
#include <functional>

#include "./centipede/shared_memory_blob_sequence.h"
#include "./common/defs.h"

namespace fuzztest::internal {

bool ExecutionMetadata::AppendCmpEntry(ByteSpan a, ByteSpan b,
                                       bool is_integer) {
  if (a.size() != b.size()) return false;
  // Size must fit in a byte.
  if (a.size() >= 256) return false;
  cmp_data.push_back(static_cast<uint8_t>(a.size()));
  cmp_data.push_back(is_integer ? 1 : 0);
  cmp_data.insert(cmp_data.end(), a.begin(), a.end());
  cmp_data.insert(cmp_data.end(), b.begin(), b.end());
  return true;
}

bool ExecutionMetadata::Write(Blob::SizeAndTagT tag,
                              BlobSequence &outputs_blobseq) const {
  return outputs_blobseq.Write({tag, cmp_data.size(), cmp_data.data()});
}

void ExecutionMetadata::Read(Blob blob) {
  cmp_data.assign(blob.data, blob.data + blob.size);
}

bool ExecutionMetadata::ForEachCmpEntry(
    const std::function<void(ByteSpan, ByteSpan, bool)>& callback) const {
  size_t i = 0;
  while (i < cmp_data.size()) {
    if (i + 2 > cmp_data.size()) return false;
    uint8_t size = cmp_data[i];
    bool is_integer = cmp_data[i + 1] != 0;
    if (i + 2 + 2 * size > cmp_data.size()) return false;
    ByteSpan a(cmp_data.data() + i + 2, size);
    ByteSpan b(cmp_data.data() + i + 2 + size, size);
    i += 2 + 2 * size;
    callback(a, b, is_integer);
  }
  return true;
}

}  // namespace fuzztest::internal
