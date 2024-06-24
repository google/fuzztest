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
#include <string>
#include <string_view>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./centipede/defs.h"
#include "./centipede/logging.h"
#include "./centipede/remote_file.h"
#include "./centipede/util.h"
#ifndef CENTIPEDE_DISABLE_RIEGELI
#include "riegeli/base/object.h"
#include "riegeli/base/types.h"
#include "riegeli/bytes/reader.h"
#include "riegeli/bytes/writer.h"
#include "riegeli/records/record_reader.h"
#include "riegeli/records/record_writer.h"
#endif  // CENTIPEDE_DISABLE_RIEGELI

namespace centipede {
namespace {

absl::Status FileWasNeverOpen(std::string_view path, RemoteFile *file,
                              bool closed) {
  std::string msg;
  if (closed) {
    msg = absl::StrCat("Already closed: ", path);
  }
  if (file != nullptr) {
    msg = absl::StrCat("Already open: ", path);
  }
  return msg.empty() ? absl::OkStatus() : absl::FailedPreconditionError(msg);
}

absl::Status FileIsOpen(std::string_view path, RemoteFile *file, bool closed) {
  std::string msg;
  if (closed) {
    msg = absl::StrCat("Already closed: ", path);
  }
  if (file == nullptr) {
    msg = absl::StrCat("Was never open: ", path);
  }
  return msg.empty() ? absl::OkStatus() : absl::FailedPreconditionError(msg);
}

absl::Status OpenFile(std::string_view path, std::string_view mode,
                      RemoteFile *&file) {
  file = RemoteFileOpen(path, mode.data());
  if (file == nullptr) {
    return absl::UnknownError(absl::StrCat("Can't open: ", path));
  }
  return absl::OkStatus();
}

absl::Status CloseFile(std::string_view path, RemoteFile *&file, bool &closed) {
  CHECK_OK(FileIsOpen(path, file, closed));
  RemoteFileClose(file);
  file = nullptr;
  closed = true;
  return absl::OkStatus();
}

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
    CHECK_OK(FileWasNeverOpen(path, file_, closed_));
    CHECK_OK(OpenFile(path, "r", file_));
    path_ = std::string(path);
    // Read the entire file at once.
    // It may be useful to read the file in chunks, but if we are going
    // to migrate to something else, it's not important here.
    ByteArray raw_bytes;
    RemoteFileRead(file_, raw_bytes);
    RemoteFileClose(file_);  // close the file here, we won't need it.
    UnpackBytesFromAppendFile(raw_bytes, &unpacked_blobs_);
    return absl::OkStatus();
  }

  absl::Status Read(ByteSpan &blob) override {
    CHECK_OK(FileIsOpen(path_, file_, closed_));
    if (next_to_read_blob_index_ == unpacked_blobs_.size())
      return absl::OutOfRangeError(absl::StrCat("No more blobs: ", path_));
    if (next_to_read_blob_index_ != 0)  // Clear the previous blob to save RAM.
      unpacked_blobs_[next_to_read_blob_index_ - 1].clear();
    blob = ByteSpan(unpacked_blobs_[next_to_read_blob_index_]);
    ++next_to_read_blob_index_;
    return absl::OkStatus();
  }

  // Closes the file (it must be open).
  absl::Status Close() override {
    CHECK_OK(CloseFile(path_, file_, closed_));
    return absl::OkStatus();
  }

 private:
  std::string path_;
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
    path_ = path;
    CHECK(mode == "w" || mode == "a") << VV(mode);
    CHECK_OK(FileWasNeverOpen(path_, file_, closed_));
    CHECK_OK(OpenFile(path_, mode, file_));
    RemoteFileSetWriteBufferSize(file_, kMaxBufferedBytes);
    return absl::OkStatus();
  }

  absl::Status Write(ByteSpan blob) override {
    CHECK_OK(FileIsOpen(path_, file_, closed_));
    ByteArray packed = PackBytesForAppendFile(blob);
    RemoteFileAppend(file_, packed);
    RemoteFileFlush(file_);
    return absl::OkStatus();
  }

  absl::Status Close() override {
    CHECK_OK(CloseFile(path_, file_, closed_));
    return absl::OkStatus();
  }

 private:
  static constexpr uint64_t kMB = 1024UL * 1024UL;
  static constexpr uint64_t kMaxBufferedBytes = 100 * kMB;

  std::string path_;
  RemoteFile *file_ = nullptr;
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

#ifndef CENTIPEDE_DISABLE_RIEGELI
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
#endif  // CENTIPEDE_DISABLE_RIEGELI

    legacy_reader_ = std::make_unique<SimpleBlobFileReader>();
    if (absl::Status s = legacy_reader_->Open(path); !s.ok()) {
      legacy_reader_ = nullptr;
      return s;
    }
    return absl::OkStatus();
  }

  absl::Status Read(ByteSpan &blob) override {
#ifdef CENTIPEDE_DISABLE_RIEGELI
    if (legacy_reader_)
      return legacy_reader_->Read(blob);
    else
      return absl::FailedPreconditionError("no reader open");
#else
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
#endif  // CENTIPEDE_DISABLE_RIEGELI
  }

  absl::Status Close() override {
#ifdef CENTIPEDE_DISABLE_RIEGELI
    legacy_reader_ = nullptr;
    return absl::OkStatus();
#else
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
#endif  // CENTIPEDE_DISABLE_RIEGELI
  }

 private:
  std::unique_ptr<SimpleBlobFileReader> legacy_reader_ = nullptr;
#ifndef CENTIPEDE_DISABLE_RIEGELI
  riegeli::RecordReader<std::unique_ptr<riegeli::Reader>> riegeli_reader_{
      riegeli::kClosed};
#endif  // CENTIPEDE_DISABLE_RIEGELI
};

#ifndef CENTIPEDE_DISABLE_RIEGELI
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
    const auto kWriterOpts =
        riegeli::RecordWriterBase::Options{}.set_chunk_size(kMaxBufferedBytes);
    writer_.Reset(CreateRiegeliFileWriter(path, mode == "a"), kWriterOpts);
    if (!writer_.ok()) return writer_.status();
    path_ = path;
    opened_at_ = absl::Now();
    flushed_at_ = absl::Now();
    written_blobs_ = 0;
    written_bytes_ = 0;
    buffered_blobs_ = 0;
    buffered_bytes_ = 0;
    return absl::OkStatus();
  }

  absl::Status Write(ByteSpan blob) override {
    const auto now = absl::Now();
    if (!PreWriteFlush(blob.size())) return writer_.status();
    if (!writer_.WriteRecord(AsStringView(blob))) return writer_.status();
    if (!PostWriteFlush(blob.size())) return writer_.status();
    write_duration_ += absl::Now() - now;
    if (written_blobs_ + buffered_blobs_ % 10000 == 0)
      VLOG(10) << "Current stats: " << StatsString();
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
    flushed_at_ = absl::Now();
    written_blobs_ += buffered_blobs_;
    written_bytes_ += buffered_bytes_;
    buffered_blobs_ = 0;
    buffered_bytes_ = 0;
    VLOG(1) << "Final stats: " << StatsString();
    return absl::OkStatus();
  }

 private:
  static constexpr uint64_t kMB = 1024UL * 1024UL;
  // Buffering/flushing control settings. The defaults were chosen based on
  // experimental runs and intuition with the idea to balance good buffering
  // performance and a steady stream of blobs being committed to the file, so
  // external readers see updates frequently enough.
  // TODO(ussuri): Once Riegeli is the sole blob writer, maybe expose these
  // as Centipede flags and plumb them through `DefaultBlobFileWriterFactory()`.
  static constexpr uint64_t kMaxBufferedBlobs = 10000;
  // Riegeli's default is 1 MB.
  static constexpr uint64_t kMaxBufferedBytes = 100 * kMB;
  static constexpr absl::Duration kMaxFlushInterval = absl::Minutes(1);
  // For each record, Riegeli also writes its offset in the stream to the file.
  static constexpr size_t kRiegeliPerRecordMetadataSize = sizeof(uint64_t);

  // Riegeli's automatic flushing occurs when it accumulates over
  // `Options::chunk_size()` of data, not on record boundaries. Our outputs
  // are continuously consumed by external readers, so we can't tolerate
  // partially written records at the end of a file. Therefore, we explicitly
  // flush when we're just about to cross the chunk size boundary, or if the
  // client writes infrequently, or if the size of records is small relative
  // to the chunk size. The latter two cases are to make the data visible to
  // readers earlier; however, note that the compression performance may
  // suffer.
  bool PreWriteFlush(size_t blob_size) {
    const auto record_size = blob_size + kRiegeliPerRecordMetadataSize;
    const std::string_view flush_reason =
        (buffered_blobs_ > kMaxBufferedBlobs)                 ? "blobs"
        : (buffered_bytes_ + record_size > kMaxBufferedBytes) ? "bytes"
        : (absl::Now() - flushed_at_ > kMaxFlushInterval)     ? "time"
                                                              : "";
    if (!flush_reason.empty()) {
      VLOG(20) << "Flushing b/c " << flush_reason << ": " << StatsString();
      if (!writer_.Flush(riegeli::FlushType::kFromMachine)) return false;
      flushed_at_ = absl::Now();
      written_blobs_ += buffered_blobs_;
      written_bytes_ += buffered_bytes_;
      buffered_blobs_ = 0;
      buffered_bytes_ = 0;
    }
    return true;
  }

  // In the rare case where the current blob itself exceeds the chunk size,
  // `Write()` will auto-flush a portion of it to the file, but the remainder
  // will remain in the buffer, so we need to force-flush it to maintain file
  // completeness.
  bool PostWriteFlush(size_t blob_size) {
    const auto record_size = blob_size + kRiegeliPerRecordMetadataSize;
    if (record_size >= kMaxBufferedBytes) {
      VLOG(20) << "Post-write flushing b/c blob size: " << StatsString();
      if (!writer_.Flush(riegeli::FlushType::kFromMachine)) return false;
      flushed_at_ = absl::Now();
      written_blobs_ += 1;
      written_bytes_ += record_size;
      buffered_blobs_ = 0;
      buffered_bytes_ = 0;
    } else {
      buffered_blobs_ += 1;
      buffered_bytes_ += record_size;
    }
    return true;
  }

  // Returns a debug string with the effective writing rate for the current file
  // path. The effective rate is measured as a ratio of the total bytes passed
  // to `Write()` and the elapsed time from the file opening till now.
  std::string StatsString() const {
    const auto opened_secs = absl::ToDoubleSeconds(absl::Now() - opened_at_);
    const auto write_secs = absl::ToDoubleSeconds(write_duration_);
    const auto total_bytes = written_bytes_ + buffered_bytes_;
    const auto throughput =
        write_secs > 0.0 ? (1.0 * total_bytes / write_secs) : 0;
    const auto file_size = writer_.EstimatedSize();
    const auto compression =
        file_size > 0 ? (1.0 * written_bytes_ / file_size) : 0;
    std::string stats = absl::StrFormat(
        "written/buffered blobs: %llu/%llu, written/buffered bytes: %llu/%llu, "
        "opened: %f sec, writing: %f sec, throughput: %.0f B/sec, "
        "file size: %llu, compression: %.1f, path: %s",
        written_blobs_, buffered_blobs_, written_bytes_, buffered_bytes_,
        opened_secs, write_secs, throughput, file_size, compression, path_);
    return stats;
  }

  // The underlying Riegeli writer.
  riegeli::RecordWriter<std::unique_ptr<riegeli::Writer>> writer_{
      riegeli::kClosed};

  // Buffering/flushing control.
  absl::Time flushed_at_ = absl::InfiniteFuture();
  uint64_t buffered_blobs_ = 0;
  uint64_t buffered_bytes_ = 0;

  // Telemetry.
  std::string path_;
  absl::Time opened_at_ = absl::InfiniteFuture();
  absl::Duration write_duration_ = absl::ZeroDuration();
  uint64_t written_blobs_ = 0;
  uint64_t written_bytes_ = 0;
};
#endif  // CENTIPEDE_DISABLE_RIEGELI

}  // namespace

std::unique_ptr<BlobFileReader> DefaultBlobFileReaderFactory() {
  return std::make_unique<DefaultBlobFileReader>();
}

std::unique_ptr<BlobFileWriter> DefaultBlobFileWriterFactory(bool riegeli) {
  if (riegeli)
#ifdef CENTIPEDE_DISABLE_RIEGELI
    LOG(FATAL) << "Riegeli unavailable: built with --use_riegeli set to false.";
#else
    return std::make_unique<RiegeliWriter>();
#endif  // CENTIPEDE_DISABLE_RIEGELI
  else
    return std::make_unique<SimpleBlobFileWriter>();
}

}  // namespace centipede
