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
#include <type_traits>

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

  // Simple TLV (tag-length-value) data structure.
  // Blob does not own the memory in `data`, just references it.
  // `size` is the number of bytes in `data`.
  // A blob with zero tag is considered invalid.
  // A blob with zero size and non-zero tag is valid but this contradicts
  // the current use.
  // TODO(kcc): [impl] replace uses of (blob.size == 0) with (!blob.IsValid()).
  // TODO(kcc): [impl] consider making it a class.
  struct Blob {
    using SizeAndTagT = size_t;
    Blob(SizeAndTagT tag, SizeAndTagT size, const uint8_t *data)
        : tag(tag), size(size), data(data) {}
    Blob() = default;  // Construct an invalid Blob.
    bool IsValid() const { return tag != 0; }

    const SizeAndTagT tag = 0;
    const SizeAndTagT size = 0;
    const uint8_t *data = nullptr;
  };

  // Writes the contents of `blob` to shared memory.
  // Returns true on success.
  // Returns false when the blob sequence is full.
  // A failed Write does not change the internal state.
  // Must not be called after Read() w/o first calling Reset().
  bool Write(Blob blob);

  // Writes `tag`/`value` as a blob. `T` should be a POD.
  // Returns true on success.
  template <typename T>
  bool Write(Blob::SizeAndTagT tag, T value) {
    static_assert(std::is_pod_v<T>, "T must be a POD");
    return Write(
        {tag, sizeof(value), reinterpret_cast<const uint8_t *>(&value)});
  }

  // Reads the next blob from the shared memory.
  // If no more blobs are left, returns a blob with size = 0.
  // Must not be called after Write() w/o first calling Reset().
  Blob Read();

  // Resets the internal state, allowing to read from or write to
  // starting from the beginning of the blob sequence.
  // Does not affect the contents of the shared memory.
  void Reset();

  // Releases shared memory used by `this`.
  void ReleaseSharedMemory();

  // Returns the number of bytes used by the shared mapping.
  // It will be zero just after creation and after the call to
  // ReleaseSharedMemory().
  size_t NumBytesUsed() const;

 private:
  // mmaps `size_` bytes from `fd_`, assigns to `data_`. Crashes on error.
  void MmapData();

  // Copy of `name` passed to CTOR.
  // If non-null, DTOR calls shm_unlink on it and frees it.
  char *name_to_unlink_ = nullptr;

  // pointer to the beginning of the shared memory region.
  // *data_ contains a sequence of {size, payload} pairs,
  // where size is 8 bytes and payload is size bytes.
  // After writing a blob, we also write 0 in place of the next blob's size,
  // if there is space left so that to overwrite any stale data left there.
  uint8_t *data_ = nullptr;
  // offset_ points to the position in data_ after last Write (or last Read).
  size_t offset_ = 0;
  size_t size_ = 0;  // size of the shared memory region.
  int fd_ = 0;       // file descriptor used to mmap the shared memory region.
  bool had_reads_after_reset_ = false;
  bool had_writes_after_reset_ = false;
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_SHARED_MEMORY_BLOB_SEQUENCE_H_
