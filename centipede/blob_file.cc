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
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "./centipede/defs.h"
#include "./centipede/logging.h"
#include "./centipede/remote_file.h"
#include "./centipede/util.h"
#include "riegeli/base/object.h"
#include "riegeli/bytes/read_all.h"
#include "riegeli/bytes/reader.h"
#include "riegeli/bytes/writer.h"
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
    if (open_ && !closed_) {
      // Virtual resolution is off in dtors, so use a specific Close().
      CHECK_OK(SimpleBlobFileReader::Close());
    }
  }

  absl::Status Open(std::string_view path) override {
    if (closed_) return absl::FailedPreconditionError("already closed");
    if (open_) return absl::FailedPreconditionError("already open");
    auto reader = CreateRiegeliFileReader(path);
    if (!reader->ok()) return reader->status();
    open_ = true;
    // Read the entire file at once.
    // It may be useful to read the file in chunks, but if we are going
    // to migrate to something else, it's not important here.
    std::string raw_bytes;
    // close the file here, we won't need it.
    absl::Status status = riegeli::ReadAll(std::move(reader), raw_bytes);
    UnpackBytesFromAppendFile(AsByteSpan(raw_bytes), &unpacked_blobs_);
    return absl::OkStatus();
  }

  absl::Status Read(ByteSpan &blob) override {
    if (closed_) return absl::FailedPreconditionError("already closed");
    if (!open_) return absl::FailedPreconditionError("was not open");
    if (next_to_read_blob_index_ == unpacked_blobs_.size())
      return absl::OutOfRangeError("no more blobs");
    if (next_to_read_blob_index_ != 0)  // Clear the previous blob to save RAM.
      unpacked_blobs_[next_to_read_blob_index_ - 1].clear();
    blob = ByteSpan(unpacked_blobs_[next_to_read_blob_index_]);
    ++next_to_read_blob_index_;
    return absl::OkStatus();
  }

  // Closes the file (it must be open).
  absl::Status Close() override {
    if (closed_) return absl::FailedPreconditionError("already closed");
    if (!open_) return absl::FailedPreconditionError("was not open");
    closed_ = true;
    // Nothing to do here, we've already closed the underlying file (in Open()).
    return absl::OkStatus();
  }

 private:
  bool open_ = false;
  bool closed_ = false;
  std::vector<ByteArray> unpacked_blobs_;
  size_t next_to_read_blob_index_ = 0;
};

// See SimpleBlobFileReader.
class SimpleBlobFileWriter : public BlobFileWriter {
 public:
  ~SimpleBlobFileWriter() override {
    if (writer_ && !closed_) {
      // Virtual resolution is off in dtors, so use a specific Close().
      CHECK_OK(SimpleBlobFileWriter::Close());
    }
  }

  absl::Status Open(std::string_view path, std::string_view mode) override {
    CHECK(mode == "w" || mode == "a") << VV(mode);
    if (closed_) return absl::FailedPreconditionError("already closed");
    if (writer_) return absl::FailedPreconditionError("already open");
    writer_ = CreateRiegeliFileWriter(path, mode == "a");
    if (!writer_->ok()) return std::exchange(writer_, nullptr)->status();
    return absl::OkStatus();
  }

  absl::Status Write(ByteSpan blob) override {
    if (closed_) return absl::FailedPreconditionError("already closed");
    if (!writer_) return absl::FailedPreconditionError("was not open");
    if (!writer_->Write(AsStringView(PackBytesForAppendFile(blob)))) {
      return writer_->status();
    }
    return absl::OkStatus();
  }

  absl::Status Close() override {
    if (closed_) return absl::FailedPreconditionError("already closed");
    if (!writer_) return absl::FailedPreconditionError("was not open");
    closed_ = true;
    if (!writer_->Close()) return writer_->status();
    return absl::OkStatus();
  }

 private:
  std::unique_ptr<riegeli::Writer> writer_;
  bool closed_ = false;
};

// Implementation of `BlobFileReader` that can read files written in legacy or
// Riegeli (https://github.com/google/riegeli) format.
class DefaultBlobFileReader : public BlobFileReader {
 public:
  ~DefaultBlobFileReader() override {
    // Virtual resolution is off in dtors, so use a specific Close().
    CHECK_OK(DefaultBlobFileReader::Close());
  }

  absl::Status Open(std::string_view path) override {
    if (absl::Status s = Close(); !s.ok()) return s;

    riegeli_reader_.Reset(CreateRiegeliFileReader(path));
    if (riegeli_reader_.CheckFileFormat()) [[likely]] {
      // File could be opened and is in the Riegeli format.
      return absl::OkStatus();
    }
    if (!riegeli_reader_.src()->ok()) [[unlikely]] {
      // File could not be opened.
      return riegeli_reader_.src()->status();
    }
    // File could be opened but is not in the Riegeli format.
    riegeli_reader_.Reset(riegeli::kClosed);

    legacy_reader_ = std::make_unique<SimpleBlobFileReader>();
    if (absl::Status s = legacy_reader_->Open(path); !s.ok()) {
      legacy_reader_ = nullptr;
      return s;
    }
    return absl::OkStatus();
  }

  absl::Status Read(ByteSpan &blob) override {
    if (legacy_reader_) [[unlikely]]
      return legacy_reader_->Read(blob);

    absl::string_view record;
    if (!riegeli_reader_.ReadRecord(record)) {
      if (riegeli_reader_.ok())
        return absl::OutOfRangeError("no more blobs");
      else
        return riegeli_reader_.status();
    }
    blob = AsByteSpan(record);
    return absl::OkStatus();
  }

  absl::Status Close() override {
    // NOLINTNEXTLINE(readability/braces). Similar to b/278586863.
    if (legacy_reader_) [[unlikely]] {
      legacy_reader_ = nullptr;
      return absl::OkStatus();
    }

    // `riegeli_reader_` not being ok will result in `Close()` failing, but its
    // non-ok status stems from a previously failed operation in an `Open()` or
    // `Read()` call whose errors were already propagated there - these are
    // therefore filtered out here.
    // `Close()` failing on an ok reader is due to the file being in an invalid
    // state that primarily arises from an incomplete concurrent write (which
    // can happen even with every write being flushed - see comment in
    // `RiegeliWriter::Write()`) - these are therefore logged but not propagated
    // as failures.
    // TODO(b/313706444): Reconsider error handling after experiments.
    // TODO(b/310701588): Try adding a test for this.
    if (riegeli_reader_.ok() && !riegeli_reader_.Close()) {
      LOG(WARNING) << "Ignoring errors while closing Riegeli file: "
                   << riegeli_reader_.status();
    }
    // Any non-ok status of `riegeli_reader_` persists for subsequent
    // operations; therefore, re-initialize it to a closed ok state.
    riegeli_reader_.Reset(riegeli::kClosed);
    return absl::OkStatus();
  }

 private:
  std::unique_ptr<SimpleBlobFileReader> legacy_reader_ = nullptr;
  riegeli::RecordReader<std::unique_ptr<riegeli::Reader>> riegeli_reader_{
      riegeli::kClosed};
};

// Implementation of `BlobFileWriter` using Riegeli
// (https://github.com/google/riegeli).
class RiegeliWriter : public BlobFileWriter {
 public:
  ~RiegeliWriter() override {
    // Virtual resolution is off in dtors, so use a specific Close().
    CHECK_OK(RiegeliWriter::Close());
  }

  absl::Status Open(std::string_view path, std::string_view mode) override {
    CHECK(mode == "w" || mode == "a") << VV(mode);
    if (absl::Status s = Close(); !s.ok()) return s;
    writer_.Reset(CreateRiegeliFileWriter(path, mode == "a"));
    if (!writer_.ok()) return writer_.status();
    return absl::OkStatus();
  }

  absl::Status Write(ByteSpan blob) override {
    if (!writer_.WriteRecord(AsStringView(blob))) return writer_.status();
    // Riegeli's automatic flushing happens in chunks, not on record boundaries.
    // Flushing explicitly after every write makes it visible to readers earlier
    // especially if writes are infrequent and/or the size of records is small
    // relative to chunk size; however, compression performance suffers with
    // more frequent flushing.
    // Writes of large chunks are not atomic. Therefore, frequent flushing can
    // still leave the file in an invalid state from a partial write which is
    // accounted for in `DefaultBlobFileReader::Close()` - however, the
    // likelihood of that is reduced since writes may be smaller.
    // TODO(b/313706444): Profile tradeoff of read freshness vs compression and
    // tune parameters accordingly.
    if (!writer_.Flush()) return writer_.status();
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
  riegeli::RecordWriter<std::unique_ptr<riegeli::Writer>> writer_{
      riegeli::kClosed};
};

std::unique_ptr<BlobFileReader> DefaultBlobFileReaderFactory() {
  return std::make_unique<DefaultBlobFileReader>();
}

std::unique_ptr<BlobFileWriter> DefaultBlobFileWriterFactory(bool riegeli) {
  if (riegeli)
    return std::make_unique<RiegeliWriter>();
  else
    return std::make_unique<SimpleBlobFileWriter>();
}

}  // namespace centipede
