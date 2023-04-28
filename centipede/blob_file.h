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

// Blob is a sequence of bytes, a BlobFile is a sequence of blobs.
// BlobFileReader reads blobs from a BlobFile.
// BlobFileWriter writes blobs to a BlobFile.
// Only one active BlobFileWriter is allowed for a given file.
// Multiple BlobFileReader objects can open the same file, concurrently
// with up to one BlobFileWriter.
// BlobFileReader/BlobFileWriter should have some level of protection against
// failed operations (may vary depending on the implementation).
// Different implementations of BlobFileReader/BlobFileWriter don't have to
// be file-format compatible.

#ifndef THIRD_PARTY_CENTIPEDE_BLOB_FILE_H_
#define THIRD_PARTY_CENTIPEDE_BLOB_FILE_H_

#include <cstdint>
#include <memory>
#include <string_view>

#include "absl/status/status.h"
#include "absl/types/span.h"
#include "./centipede/defs.h"

namespace centipede {

// Reads blobs from a BlobFile. See the top file comment.
class BlobFileReader {
 public:
  BlobFileReader() = default;
  // Implementations must take care to call their Close() in the dtor, unless
  // the client has already explicitly called it.
  virtual ~BlobFileReader() = default;

  // Not copyable or movable.
  BlobFileReader(const BlobFileReader &) = delete;
  BlobFileReader &operator=(const BlobFileReader &) = delete;
  BlobFileReader(BlobFileReader &&) = delete;
  BlobFileReader &operator=(BlobFileReader &&) = delete;

  // Opens the file `path`.
  // Implementations must ensure that this is called only once.
  virtual absl::Status Open(std::string_view path) = 0;

  // Reads one `blob` from an open file.
  // Implementations must ensure that the memory wrapped by `blob` remains valid
  // until the next Read() or Close() call.
  // Returns absl::OutOfRangeError when there are no more blobs to read.
  virtual absl::Status Read(absl::Span<uint8_t> &blob) = 0;

  // Closes the file, which was previously opened and never closed.
  virtual absl::Status Close() = 0;
};

// Writes blobs to a BlobFile. See the top file comment.
class BlobFileWriter {
 public:
  BlobFileWriter() = default;
  // Implementations must take care to call their Close() in the dtor, unless
  // the client has already explicitly called it.
  virtual ~BlobFileWriter() = default;

  // Not copyable or movable.
  BlobFileWriter(const BlobFileWriter &) = delete;
  BlobFileWriter &operator=(const BlobFileWriter &) = delete;
  BlobFileWriter(BlobFileWriter &&) = delete;
  BlobFileWriter &operator=(BlobFileWriter &&) = delete;

  // Opens the file `path` with mode `mode` (which must be either "w" or "a" at
  // the moment). Implementations must ensure that this is called only once.
  virtual absl::Status Open(std::string_view path, std::string_view mode) = 0;

  // Writes `blob` to this file. Implementations must ensure that the file has
  // been opened.
  virtual absl::Status Write(absl::Span<const uint8_t> blob) = 0;

  // Same as above, but for `ByteArray`.
  absl::Status Write(const ByteArray &bytes) {
    return Write(absl::Span<const uint8_t>{bytes});
  }

  // Closes the file, which was previously opened and never closed.
  virtual absl::Status Close() = 0;
};

// Creates a new object of a default implementation of BlobFileReader.
std::unique_ptr<BlobFileReader> DefaultBlobFileReaderFactory();

// Creates a new object of a default implementation of BlobFileWriter.
std::unique_ptr<BlobFileWriter> DefaultBlobFileWriterFactory();

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_BLOB_FILE_H_
