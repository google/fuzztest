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

#include <cstdint>
#include <functional>
#include <string_view>

#include "./centipede/shared_memory_blob_sequence.h"
#include "./common/defs.h"

namespace fuzztest::internal {

struct ExecutionMetadata {
  // Appends a CMP entry comparing `a` and `b` to the metadata. Returns false if
  // the entry cannot be appended. Return true otherwise.
  bool AppendCmpEntry(ByteSpan a, ByteSpan b);

  // Enumerates through all CMP entries in the metadata by calling
  // `callback` on each of them. Returns false if there are invalid
  // entries. Returns true otherwise.
  bool ForEachCmpEntry(std::function<void(ByteSpan, ByteSpan)> callback) const;

  // Writes the contents to `outputs_blobseq` with header `tag`. Returns true
  // iff successful.
  bool Write(Blob::SizeAndTagT tag, BlobSequence &outputs_blobseq) const;

  // Reads the contents from `blob`.
  //
  // Note that the method does not check the blob tag, it should be checked by
  // the method users.
  void Read(Blob blob);

  // CMP entries are stored in one large ByteArray to minimize RAM consumption.
  // One CMP arg pair is stored as
  //  * `size` (1-byte value)
  //  * `value0` (`size` bytes)
  //  * `value1` (`size` bytes)
  ByteArray cmp_data;
};

// Incremental differential fuzzing (`fuzztest::RecordOrDiff`) envelope.
//
// When the diff mode is active, `ExecutionMetadata::cmp_data` carries this
// envelope in both directions instead of raw CMP entries:
//
//   offset 0 : 8 bytes  magic = kDiffEnvelopeMagic
//   offset 8 : uint8    kind (DiffEnvelopeKind)
//   offset 9 : uint64   cmp_size (host byte order, unaligned)
//   offset 17: cmp_size bytes of CMP entries (the plain `cmp_data` format)
//   next     : uint64   diff_size
//   next     : diff_size bytes of payload
//   (no trailing bytes)
//
// The payload of kExpectations/kRecords is a record container, which is opaque
// to Centipede and owned by the framework. kAck and kSkippedUnparsable have an
// empty payload. Outside the diff mode, the bytes on the wire are unchanged.
inline constexpr std::string_view kDiffEnvelopeMagic = "FTDIFF01";

enum class DiffEnvelopeKind : uint8_t {
  // Controller -> worker (validate): the baseline record container.
  kExpectations = 0,
  // Worker -> controller (record): the record container of the execution.
  kRecords = 1,
  // Worker -> controller (validate): the input was compared (empty payload).
  kAck = 2,
  // Worker -> controller (both modes): the input could not be parsed by the
  // current domains, so nothing was recorded or compared (empty payload).
  kSkippedUnparsable = 3,
};

// The per-input diff result produced by the runner callbacks.
struct DiffResult {
  DiffEnvelopeKind kind;
  ByteArray payload;
};

// Returns the envelope of `kind` wrapping `cmp_data` and `payload`.
ByteArray EncodeDiffEnvelope(DiffEnvelopeKind kind, ByteSpan cmp_data,
                             ByteSpan payload);

// Decodes `bytes` as a diff envelope. Returns false (and leaves the outputs
// untouched) if `bytes` is not a well-formed envelope. On success, `cmp_data`
// and `payload` point into `bytes`.
bool DecodeDiffEnvelope(ByteSpan bytes, DiffEnvelopeKind& kind,
                        ByteSpan& cmp_data, ByteSpan& payload);

}  // namespace fuzztest::internal

#endif  // THIRD_PARTY_CENTIPEDE_EXECUTION_METADATA_H_
