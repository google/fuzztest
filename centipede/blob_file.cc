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

#include "./centipede/blob_file.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

#include "absl/status/status.h"
#include "absl/types/span.h"
#include "./centipede/defs.h"
#include "./centipede/logging.h"
#include "./centipede/remote_file.h"
#include "./centipede/util.h"
#include "riegeli/base/object.h"
#include "riegeli/bytes/fd_reader.h"
#include "riegeli/bytes/fd_writer.h"
#include "riegeli/records/record_reader.h"
#include "riegeli/records/record_writer.h"

namespace centipede {

// TODO(ussuri): Return more informative statuses, at least with the file path
//  included. That will require adjustments in the test: use
//  `testing::status::StatusIs` instead of direct `absl::Status` comparisons).

// Simple implementations of `BlobFileReader` / `BlobFileWriter` based on
// `PackBytesForAppendFile()` / `UnpackBytesFromAppendFile()`.
// We expect to eventually replace this code with something more robust,
// and efficient, e.g. possibly https://github.com/google/riegeli.
// But the current implementation is fully functional.
class SimpleBlobFileReader : public BlobFileReader {
 public:
  ~SimpleBlobFileReader() override {
    if (file_ && !closed_) {
      // Virtual resolution is off in dtors, so use a specific Close().
      CHECK_OK(SimpleBlobFileReader::Close());
    }
  }

  absl::Status Open(std::string_view path) override {
    if (closed_) return absl::FailedPreconditionError("already closed");
    if (file_) return absl::FailedPreconditionError("already open");
    file_ = RemoteFileOpen(path, "r");
    if (file_ == nullptr) return absl::UnknownError("can't open file");
    // Read the entire file at once.
    // It may be useful to read the file in chunks, but if we are going
    // to migrate to something else, it's not important here.
    ByteArray raw_bytes;
    RemoteFileRead(file_, raw_bytes);
    RemoteFileClose(file_);  // close the file here, we won't need it.
    UnpackBytesFromAppendFile(raw_bytes, &unpacked_blobs_);
    return absl::OkStatus();
  }

  absl::Status Read(absl::Span<const uint8_t> &blob) override {
    if (closed_) return absl::FailedPreconditionError("already closed");
    if (!file_) return absl::FailedPreconditionError("was not open");
    if (next_to_read_blob_index_ == unpacked_blobs_.size())
      return absl::OutOfRangeError("no more blobs");
    if (next_to_read_blob_index_ != 0)  // Clear the previous blob to save RAM.
      unpacked_blobs_[next_to_read_blob_index_ - 1].clear();
    blob = absl::Span<const uint8_t>(unpacked_blobs_[next_to_read_blob_index_]);
    ++next_to_read_blob_index_;
    return absl::OkStatus();
  }

  // Closes the file (it must be open).
  absl::Status Close() override {
    if (closed_) return absl::FailedPreconditionError("already closed");
    if (!file_) return absl::FailedPreconditionError("was not open");
    closed_ = true;
    // Nothing to do here, we've already closed the underlying file (in Open()).
    return absl::OkStatus();
  }

 private:
  RemoteFile *file_ = nullptr;
  bool closed_ = false;
  std::vector<ByteArray> unpacked_blobs_;
  size_t next_to_read_blob_index_ = 0;
};

// See SimpleBlobFileReader.
class SimpleBlobFileWriter : public BlobFileWriter {
 public:
  ~SimpleBlobFileWriter() override {
    if (file_ && !closed_) {
      // Virtual resolution is off in dtors, so use a specific Close().
      CHECK_OK(SimpleBlobFileWriter::Close());
    }
  }

  absl::Status Open(std::string_view path, std::string_view mode) override {
    CHECK(mode == "w" || mode == "a") << VV(mode);
    if (closed_) return absl::FailedPreconditionError("already closed");
    if (file_) return absl::FailedPreconditionError("already open");
    file_ = RemoteFileOpen(path, mode.data());
    if (file_ == nullptr) return absl::UnknownError("can't open file");
    return absl::OkStatus();
  }

  absl::Status Write(absl::Span<const uint8_t> blob) override {
    if (closed_) return absl::FailedPreconditionError("already closed");
    if (!file_) return absl::FailedPreconditionError("was not open");
    // TODO(kcc): [as-needed] This copy from a span to vector is clumsy. Change
    //  RemoteFileAppend to accept a span.
    ByteArray bytes(blob.begin(), blob.end());
    ByteArray packed = PackBytesForAppendFile(bytes);
    RemoteFileAppend(file_, packed);

    return absl::OkStatus();
  }

  absl::Status Close() override {
    if (closed_) return absl::FailedPreconditionError("already closed");
    if (!file_) return absl::FailedPreconditionError("was not open");
    closed_ = true;
    RemoteFileClose(file_);
    return absl::OkStatus();
  }

 private:
  RemoteFile *file_ = nullptr;
  bool closed_ = false;
};

// Implementations of `BlobFileReader`/`BlobFileWriter` based on Riegeli
// (https://github.com/google/riegeli).
class RiegeliReader : public BlobFileReader {
 public:
  ~RiegeliReader() override {
    // Virtual resolution is off in dtors, so use a specific Close().
    CHECK_OK(RiegeliReader::Close());
  }

  absl::Status Open(std::string_view path) override {
    if (absl::Status s = Close(); !s.ok()) return s;
    reader_.Reset(riegeli::FdReader(path));
    if (!reader_.ok()) return reader_.status();
    return absl::OkStatus();
  }

  absl::Status Read(absl::Span<const uint8_t> &blob) override {
    absl::string_view record;
    if (!reader_.ReadRecord(record)) {
      if (reader_.ok())
        return absl::OutOfRangeError("no more blobs");
      else
        return reader_.status();
    }
    blob = absl::Span<const uint8_t>(
        reinterpret_cast<const uint8_t *>(record.data()), record.size());
    return absl::OkStatus();
  }

  absl::Status Close() override {
    // Reader already being in a bad state will result in close failure but
    // those errors have already been reported.
    if (!reader_.ok()) {
      reader_.Reset(riegeli::kClosed);
      return absl::OkStatus();
    }
    if (!reader_.Close()) return reader_.status();
    return absl::OkStatus();
  }

 private:
  riegeli::RecordReader<riegeli::FdReader<>> reader_{riegeli::kClosed};
};

class RiegeliWriter : public BlobFileWriter {
 public:
  ~RiegeliWriter() override {
    // Virtual resolution is off in dtors, so use a specific Close().
    CHECK_OK(RiegeliWriter::Close());
  }

  absl::Status Open(std::string_view path, std::string_view mode) override {
    CHECK(mode == "w" || mode == "a") << VV(mode);
    if (absl::Status s = Close(); !s.ok()) return s;
    writer_.Reset(riegeli::FdWriter(
        path, riegeli::FdWriterBase::Options().set_append(mode == "a")));
    if (!writer_.ok()) return writer_.status();
    return absl::OkStatus();
  }

  absl::Status Write(absl::Span<const uint8_t> blob) override {
    if (!writer_.WriteRecord(absl::string_view(
            reinterpret_cast<const char *>(blob.data()), blob.size()))) {
      return writer_.status();
    }
    return absl::OkStatus();
  }

  absl::Status Close() override {
    // Writer already being in a bad state will result in close failure but
    // those errors have already been reported.
    if (!writer_.ok()) {
      writer_.Reset(riegeli::kClosed);
      return absl::OkStatus();
    }
    if (!writer_.Close()) return writer_.status();
    return absl::OkStatus();
  }

 private:
  riegeli::RecordWriter<riegeli::FdWriter<>> writer_{riegeli::kClosed};
};

std::unique_ptr<BlobFileReader> DefaultBlobFileReaderFactory(bool riegeli) {
  if (riegeli)
    return std::make_unique<RiegeliReader>();
  else
    return std::make_unique<SimpleBlobFileReader>();
}

std::unique_ptr<BlobFileWriter> DefaultBlobFileWriterFactory(bool riegeli) {
  if (riegeli)
    return std::make_unique<RiegeliWriter>();
  else
    return std::make_unique<SimpleBlobFileWriter>();
}

}  // namespace centipede
