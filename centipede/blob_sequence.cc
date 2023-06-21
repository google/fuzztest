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

#include "./centipede/blob_sequence.h"

#include <string.h>

#include <cstdio>
#include <cstdlib>

#include "./centipede/error_on_failure.h"

namespace centipede {

BlobSequence::BlobSequence(uint8_t* data, size_t size)
    : data_(data), size_(size) {
  ErrorOnFailure(size < sizeof(Blob::size), "Size too small");
}

bool BlobSequence::Write(Blob blob) {
  ErrorOnFailure(!blob.IsValid(), "Write(): blob.tag must not be zero");
  ErrorOnFailure(had_reads_after_reset_, "Write(): Had reads after reset");
  had_writes_after_reset_ = true;
  if (offset_ + sizeof(blob.size) + sizeof(blob.tag) + blob.size > size_) {
    return false;
  }
  // Write tag.
  memcpy(data_ + offset_, &blob.tag, sizeof(blob.tag));
  offset_ += sizeof(blob.tag);

  // Write size.
  memcpy(data_ + offset_, &blob.size, sizeof(blob.size));
  offset_ += sizeof(blob.size);
  // Write data.
  memcpy(data_ + offset_, blob.data, blob.size);
  offset_ += blob.size;
  if (offset_ + sizeof(blob.size) + sizeof(blob.tag) <= size_) {
    // Write zero tag/size to data_+offset_ but don't change the offset.
    // This is required to overwrite any stale bits in data_.
    Blob invalid_blob;  // invalid.
    memcpy(data_ + offset_, &invalid_blob.tag, sizeof(invalid_blob.tag));
    memcpy(data_ + offset_ + sizeof(invalid_blob.tag), &invalid_blob.size,
           sizeof(invalid_blob.size));
  }
  return true;
}

Blob BlobSequence::Read() {
  ErrorOnFailure(had_writes_after_reset_, "Had writes after reset");
  had_reads_after_reset_ = true;
  if (offset_ + sizeof(Blob::size) + sizeof(Blob::tag) >= size_) return {};
  // Read blob_tag.
  Blob::SizeAndTagT blob_tag = 0;
  memcpy(&blob_tag, data_ + offset_, sizeof(blob_tag));
  offset_ += sizeof(blob_tag);
  // Read blob_size.
  Blob::SizeAndTagT blob_size = 0;
  memcpy(&blob_size, data_ + offset_, sizeof(Blob::size));
  offset_ += sizeof(Blob::size);
  // Read blob_data.
  ErrorOnFailure(offset_ + blob_size > size_, "Not enough bytes");
  if (blob_tag == 0 && blob_size == 0) return {};
  ErrorOnFailure(blob_tag == 0, "Read: blob.tag must not be zero");
  Blob result{blob_tag, blob_size, data_ + offset_};
  offset_ += result.size;
  return result;
}

void BlobSequence::Reset() {
  offset_ = 0;
  had_reads_after_reset_ = false;
  had_writes_after_reset_ = false;
}

}  // namespace centipede
