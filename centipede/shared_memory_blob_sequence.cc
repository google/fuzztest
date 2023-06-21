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
#include <sys/types.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <memory>

#include "./centipede/blob_sequence.h"
#include "./centipede/error_on_failure.h"

namespace centipede {

SharedMemoryBlobSequence::SharedMemoryBlobSequence(const char *name,
                                                   size_t size)
    : size_(size) {
  ErrorOnFailure(size < sizeof(Blob::size), "Size too small");
  fd_ = shm_open(name, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
  name_to_unlink_ = strdup(name);  // Using raw C strings to avoid dependencies.
  ErrorOnFailure(fd_ < 0, "shm_open() failed");
  ErrorOnFailure(ftruncate(fd_, static_cast<__off_t>(size_)),
                 "ftruncate() failed)");
  uint8_t *data = MmapData();
  blob_seq_ = std::make_unique<BlobSequence>(data, size_);
}

SharedMemoryBlobSequence::SharedMemoryBlobSequence(const char *name) {
  fd_ = shm_open(name, O_RDWR, 0);
  ErrorOnFailure(fd_ < 0, "shm_open() failed");
  struct stat statbuf = {};
  ErrorOnFailure(fstat(fd_, &statbuf), "fstat() failed");
  size_ = statbuf.st_size;
  uint8_t *data = MmapData();
  blob_seq_ = std::make_unique<BlobSequence>(data, size_);
}

uint8_t *SharedMemoryBlobSequence::MmapData() {
  uint8_t *data = static_cast<uint8_t *>(
      mmap(nullptr, size_, PROT_READ | PROT_WRITE, MAP_SHARED, fd_, 0));
  ErrorOnFailure(data == MAP_FAILED, "mmap() failed");
  return data;
}

SharedMemoryBlobSequence::~SharedMemoryBlobSequence() {
  ErrorOnFailure(munmap(blob_seq_->data(), size_), "munmap() failed");
  if (name_to_unlink_) {
    ErrorOnFailure(shm_unlink(name_to_unlink_), "shm_unlink() failed");
    free(name_to_unlink_);
  }
  ErrorOnFailure(close(fd_), "close() failed");
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

}  // namespace centipede
