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

#ifndef THIRD_PARTY_CENTIPEDE_SHARED_MEMORY_BLOB_SEQUENCE_H_
#define THIRD_PARTY_CENTIPEDE_SHARED_MEMORY_BLOB_SEQUENCE_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "./centipede/blob_sequence.h"

// This library must not depend on anything other than libc,
// so that it does not introduce any dependencies to its users.
// Any such dependencies may get coverage-instrumented, introducing noise
// into coverage reporting.
// Small exceptions for header-only parts of STL may be possible.

namespace centipede {

// SharedMemoryBlobSequence:
// enables inter-process communication via shared memory.
//
// It allows one process to write some data, then another process to read it.
// SharedMemoryBlobSequence is thread-compatible.
// It does not perform any inter-process synchronization itself, but relies on
// external synchronization e.g. via process fork/join or semaphores.
//
// Typical usage is to create a SharedMemoryBlobSequence in one process and then
// open SharedMemoryBlobSequence with the same name in another process.
// But it can be done in the same process too.
//
// Usage example:
//  void ParentProcess() {
//    // Create a new blob sequence.
//    SharedMemoryBlobSequence parent("/foo", 1000);
//
//    // Parent process writes some data to the shared blob:
//    parent.Write({some_data, some_data_size});
//    parent.Write({some_other_data, some_other_data_size});
//
//    // Run the child process.
//    ExecuteChildProcessAndWaitUntilItIsDone();
//  }
//
//  void Child() {
//    // Open an existing blob sequence.
//    SharedMemoryBlobSequence child("/foo");
//
//    // Read the data written by parent.
//    while (true) {
//      auto blob = parent.Read();
//      if (!blob.size) break;
//      Use({blob.data, blob.size});
//    }
//  }
//
class SharedMemoryBlobSequence {
 public:
  // Creates a new shared blob sequence named `name`.
  // `name` follows the rules for shm_open.
  // Aborts on any failure.
  // `size` is the size of the shared memory region in bytes, must be >= 8.
  // The amount of actual data that can be written is slightly less.
  SharedMemoryBlobSequence(const char *name, size_t size);

  // Opens an existing shared blob sequence named `name`.
  // Aborts on any failure.
  explicit SharedMemoryBlobSequence(const char *name);

  // Releases all resources.
  ~SharedMemoryBlobSequence();

  // Releases shared memory used by `this`.
  void ReleaseSharedMemory();

  // Returns the number of bytes used by the shared mapping.
  // It will be zero just after creation and after the call to
  // ReleaseSharedMemory().
  size_t NumBytesUsed() const;

  // Returns the stored sequence of blobs.
  BlobSequence &blob_seq() const { return *blob_seq_; }

 private:
  // mmaps `size_` bytes from `fd_`, returns the starting address for the new
  // mapping. Crashes on error.
  uint8_t *MmapData();

  // Copy of `name` passed to CTOR.
  // If non-null, DTOR calls shm_unlink on it and frees it.
  char *name_to_unlink_ = nullptr;

  // pointer to the beginning of the shared memory region.
  size_t size_ = 0;  // size of the shared memory region.
  int fd_ = 0;       // file descriptor used to mmap the shared memory region.
  std::unique_ptr<BlobSequence> blob_seq_ =
      nullptr;  // the stored sequence of Blobs in the shared memory region.
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_SHARED_MEMORY_BLOB_SEQUENCE_H_
