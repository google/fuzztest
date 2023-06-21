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

#ifndef THIRD_PARTY_CENTIPEDE_BLOB_SEQUENCE_H_
#define THIRD_PARTY_CENTIPEDE_BLOB_SEQUENCE_H_

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <vector>

// This library must not depend on anything other than libc,
// so that it does not introduce any dependencies to its users.
// Any such dependencies may get coverage-instrumented, introducing noise
// into coverage reporting.
// Small exceptions for header-only parts of STL may be possible.

namespace centipede {

// Simple TLV (tag-length-value) data structure.
// Blob does not own the memory in `data`, just references it.
// `size` is the number of bytes in `data`.
// A blob with zero tag is considered invalid.
// A blob with zero size and non-zero tag is valid but this contradicts
// the current use.
struct Blob {
  // TODO(kcc): [impl] replace uses of (blob.size == 0) with (!blob.IsValid()).
  // TODO(kcc): [impl] consider making it a class.
  using SizeAndTagT = size_t;
  Blob(SizeAndTagT tag, SizeAndTagT size, const uint8_t* data)
      : tag(tag), size(size), data(data) {}
  Blob() = default;  // Construct an invalid Blob.
  bool IsValid() const { return tag != 0; }

  static std::vector<uint8_t> EncodeVecFromBlob(const Blob& blob) {
    return {blob.data, blob.data + blob.size};
  }

  static Blob EncodeBlobFromVec(const std::vector<uint8_t>& vec,
                                uint64_t tag = 1) {
    return {tag, vec.size(), vec.data()};
  }

  const SizeAndTagT tag = 0;
  const SizeAndTagT size = 0;
  const uint8_t* data = nullptr;
};

// The BlobSequence is a consecutive sequence of Blobs.
class BlobSequence {
 public:
  // Creates a new blob sequence of arbitrary `data` with given `size` in bytes,
  // must be >= 8. Aborts on any failure. The amount of actual data that can be
  // written is slightly less.
  explicit BlobSequence(uint8_t* data, size_t size);

  // Writes the contents of `blob` to the blob sequence.
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
        {tag, sizeof(value), reinterpret_cast<const uint8_t*>(&value)});
  }

  // Reads the next blob from the sequence.
  // If no more blobs are left, returns a blob with size = 0.
  // Must not be called after Write() w/o first calling Reset().
  Blob Read();

  // Resets the internal state, allowing to read from or write to
  // starting from the beginning of the blob sequence.
  void Reset();

  uint8_t* data() const { return data_; }

  // The position after last Write (or last Read).
  size_t offset() const { return offset_; }

 private:
  // data_ contains a sequence of {size, payload} pairs,
  // where size is 8 bytes and payload is size bytes.
  // After writing a blob, we also write 0 in place of the next blob's size,
  // if there is space left so that to overwrite any stale data left there.
  uint8_t* data_ = nullptr;
  // offset_ points to the position in data_ after last Write (or last Read).
  size_t offset_ = 0;
  size_t size_ = 0;
  bool had_reads_after_reset_ = false;
  bool had_writes_after_reset_ = false;
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_BLOB_SEQUENCE_H_
