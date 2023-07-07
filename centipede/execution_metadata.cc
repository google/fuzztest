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

namespace centipede {

bool ExecutionMetadata::ForEachCmpEntry(
    std::function<void(ByteSpan, ByteSpan)> callback) const {
  size_t i = 0;
  while (i < cmp_data.size()) {
    auto size = cmp_data[i];
    if (i + 2 * size + 1 > cmp_data.size()) return false;
    ByteSpan a(cmp_data.data() + i + 1, size);
    ByteSpan b(cmp_data.data() + i + size + 1, size);
    i += 1 + 2 * size;
    callback(a, b);
  }
  return true;
}

}  // namespace centipede
