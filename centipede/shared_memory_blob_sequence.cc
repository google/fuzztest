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

#include "./centipede/shared_memory_blob_sequence.h"

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>

namespace centipede {

static void ErrorOnFailure(bool condition, const char *text) {
  if (!condition) return;
  std::perror(text);
  abort();
}

SharedMemoryBlobSequence::SharedMemoryBlobSequence(const char *name,
                                                   size_t size)
    : size_(size) {
  ErrorOnFailure(size < sizeof(Blob::size), "Size too small");
  fd_ = shm_open(name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  name_to_unlink_ = strdup(name);  // Using raw C strings to avoid dependencies.
  ErrorOnFailure(fd_ < 0, "shm_open() failed");
  ErrorOnFailure(ftruncate(fd_, static_cast<__off_t>(size_)),
                 "ftruncate() failed)");
  MmapData();
}

SharedMemoryBlobSequence::SharedMemoryBlobSequence(const char *name) {
  fd_ = shm_open(name, O_RDWR, 0);
  ErrorOnFailure(fd_ < 0, "shm_open() failed");
  struct stat statbuf = {};
  ErrorOnFailure(fstat(fd_, &statbuf), "fstat() failed");
  size_ = statbuf.st_size;
  MmapData();
}

void SharedMemoryBlobSequence::MmapData() {
  data_ = static_cast<uint8_t *>(
      mmap(nullptr, size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0));
  ErrorOnFailure(data_ == MAP_FAILED, "mmap() failed");
}

SharedMemoryBlobSequence::~SharedMemoryBlobSequence() {
  ErrorOnFailure(munmap(data_, size_), "munmap() failed");
  if (name_to_unlink_) {
    ErrorOnFailure(shm_unlink(name_to_unlink_), "shm_unlink() failed");
    free(name_to_unlink_);
  }
  ErrorOnFailure(close(fd_), "close() failed");
}

void SharedMemoryBlobSequence::Reset() {
  offset_ = 0;
  had_reads_after_reset_ = false;
  had_writes_after_reset_ = false;
}

void SharedMemoryBlobSequence::ReleaseSharedMemory() {
  // Setting size to 0 releases the memory to OS.
  ErrorOnFailure(ftruncate(fd_, 0) != 0, "ftruncate(0) failed)");
  // Set the size back to `size`. The memory is not actually reserved.
  ErrorOnFailure(ftruncate(fd_, size_) != 0, "ftruncate(size_) failed)");
}

size_t SharedMemoryBlobSequence::NumBytesUsed() const {
  struct stat statbuf;
  ErrorOnFailure(fstat(fd_, &statbuf), "fstat() failed)");
  return statbuf.st_blocks * S_BLKSIZE;
}

bool SharedMemoryBlobSequence::Write(Blob blob) {
  ErrorOnFailure(!blob.IsValid(), "Write(): blob.tag must not be zero");
  ErrorOnFailure(had_reads_after_reset_, "Write(): Had reads after reset");
  had_writes_after_reset_ = true;
  if (offset_ + sizeof(blob.size) + sizeof(blob.tag) + blob.size > size_)
    return false;
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

SharedMemoryBlobSequence::Blob SharedMemoryBlobSequence::Read() {
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

}  // namespace centipede
