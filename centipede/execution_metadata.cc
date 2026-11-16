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
#include <cstring>
#include <functional>

#include "./centipede/shared_memory_blob_sequence.h"
#include "./common/defs.h"

namespace fuzztest::internal {

bool ExecutionMetadata::AppendCmpEntry(ByteSpan a, ByteSpan b) {
  if (a.size() != b.size()) return false;
  // Size must fit in a byte.
  if (a.size() >= 256) return false;
  cmp_data.push_back(a.size());
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

namespace {

constexpr size_t kDiffEnvelopeKindOffset = kDiffEnvelopeMagic.size();
constexpr size_t kDiffEnvelopeCmpSizeOffset = kDiffEnvelopeKindOffset + 1;
constexpr size_t kDiffEnvelopeMinSize =
    kDiffEnvelopeCmpSizeOffset + 2 * sizeof(uint64_t);

void AppendUint64(ByteArray& out, uint64_t value) {
  const auto* bytes = reinterpret_cast<const uint8_t*>(&value);
  out.insert(out.end(), bytes, bytes + sizeof(value));
}

// Reads a uint64 at `offset` of `bytes`, advancing `offset`. Returns false if
// there are not enough bytes.
bool ReadUint64(ByteSpan bytes, size_t& offset, uint64_t& value) {
  if (bytes.size() < offset || bytes.size() - offset < sizeof(value)) {
    return false;
  }
  std::memcpy(&value, bytes.data() + offset, sizeof(value));
  offset += sizeof(value);
  return true;
}

}  // namespace

ByteArray EncodeDiffEnvelope(DiffEnvelopeKind kind, ByteSpan cmp_data,
                             ByteSpan payload) {
  ByteArray result;
  result.reserve(kDiffEnvelopeMinSize + cmp_data.size() + payload.size());
  result.insert(result.end(), kDiffEnvelopeMagic.begin(),
                kDiffEnvelopeMagic.end());
  result.push_back(static_cast<uint8_t>(kind));
  AppendUint64(result, cmp_data.size());
  result.insert(result.end(), cmp_data.begin(), cmp_data.end());
  AppendUint64(result, payload.size());
  result.insert(result.end(), payload.begin(), payload.end());
  return result;
}

bool DecodeDiffEnvelope(ByteSpan bytes, DiffEnvelopeKind& kind,
                        ByteSpan& cmp_data, ByteSpan& payload) {
  if (bytes.size() < kDiffEnvelopeMinSize) return false;
  if (std::memcmp(bytes.data(), kDiffEnvelopeMagic.data(),
                  kDiffEnvelopeMagic.size()) != 0) {
    return false;
  }
  const uint8_t raw_kind = bytes[kDiffEnvelopeKindOffset];
  if (raw_kind > static_cast<uint8_t>(DiffEnvelopeKind::kSkippedUnparsable)) {
    return false;
  }
  const auto decoded_kind = static_cast<DiffEnvelopeKind>(raw_kind);
  size_t offset = kDiffEnvelopeCmpSizeOffset;
  uint64_t cmp_size = 0;
  if (!ReadUint64(bytes, offset, cmp_size)) return false;
  if (bytes.size() - offset < cmp_size) return false;
  const size_t cmp_offset = offset;
  offset += static_cast<size_t>(cmp_size);
  uint64_t diff_size = 0;
  if (!ReadUint64(bytes, offset, diff_size)) return false;
  // No trailing bytes are allowed.
  if (bytes.size() - offset != diff_size) return false;
  if ((decoded_kind == DiffEnvelopeKind::kAck ||
       decoded_kind == DiffEnvelopeKind::kSkippedUnparsable) &&
      diff_size != 0) {
    return false;
  }
  kind = decoded_kind;
  // Construct `ByteSpan` from `(data, size)` rather than `subspan()`, which
  // pulls `absl::ThrowStdOutOfRange` / `RawLog` (and its sancov PCs) into
  // runner binaries.
  cmp_data = ByteSpan(bytes.data() + cmp_offset, static_cast<size_t>(cmp_size));
  payload = ByteSpan(bytes.data() + offset, static_cast<size_t>(diff_size));
  return true;
}

}  // namespace fuzztest::internal
