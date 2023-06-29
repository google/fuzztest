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

// Abstraction of metadata collected from executions that does not
// contribute to coverage but can be useful in mutation.
//
// This library is for both engine and runner.

#ifndef THIRD_PARTY_CENTIPEDE_EXECUTION_METADATA_H_
#define THIRD_PARTY_CENTIPEDE_EXECUTION_METADATA_H_

#include "./centipede/defs.h"
#include "./centipede/shared_memory_blob_sequence.h"

namespace centipede {

struct ExecutionMetadata {
  // CMP entires are stored in one large ByteArray to minimize RAM consumption.
  // One CMP arg pair is stored as
  //  * `size` (1-byte value)
  //  * `value0` (`size` bytes)
  //  * `value1` (`size` bytes)
  ByteArray cmp_data;

  // Appends a CMP entry comparing `a` and `b` to the metadata. Returns false if
  // the entry cannot be appended. Return true otherwise.
  bool AppendCmpEntry(ByteSpan a, ByteSpan b);

  // Writes the contents to `outputs_blobseq` with header `tag`. Returns false
  // if the write failed. Returns true otherwise.
  bool Write(Blob::SizeAndTagT tag,
             SharedMemoryBlobSequence &outputs_blobseq) const;

  // Reads the contents from `blob`.
  void Read(Blob blob);

  // Enumerates through all CMP entries in the metadata by calling
  // `callback` on each of them. Returns false if there are invalid
  // entires. Returns true otherwise.
  bool ForEachCmpEntry(std::function<void(ByteSpan, ByteSpan)> callback) const;
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_EXECUTION_METADATA_H_
