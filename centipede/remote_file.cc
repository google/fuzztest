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

// Implementation of remote_file.h for the local file system using pure Standard
// Library APIs.

#include "./centipede/remote_file.h"

#include <glob.h>
#include <sys/stat.h>

#include <cstdint>
#include <cstdio>
#include <filesystem>  // NOLINT
#include <memory>
#include <string>
#include <string_view>
#include <system_error>  // NOLINT
#include <vector>

#include "absl/base/attributes.h"
#include "absl/base/nullability.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "./centipede/logging.h"
#include "./common/defs.h"
#ifndef CENTIPEDE_DISABLE_RIEGELI
#include "riegeli/bytes/fd_reader.h"
#include "riegeli/bytes/fd_writer.h"
#include "riegeli/bytes/reader.h"
#include "riegeli/bytes/writer.h"
#endif  // CENTIPEDE_DISABLE_RIEGELI

namespace centipede {

namespace {

// A basic version of "remote file" that can only actually handle local files.
// This provides a polyfill that enables running Centipede on local filesystems.
// It can be replaced by an implementation for an actual remote filesystem by
// overriding some of the weak symbols below (the ones that either return or
// take a `RemoteFile *` param).
// TODO(ussuri): This stops just one step away from making `RemoteFile` an
//  abstract virtual base. Measure the performance of doing so and maybe switch.
class LocalRemoteFile : public RemoteFile {
 public:
  static LocalRemoteFile *Create(std::string_view path, std::string_view mode) {
    FILE *file = std::fopen(path.data(), mode.data());
    if (file == nullptr) {
      LOG(ERROR) << "Failed to open file: " << VV(path);
      return nullptr;
    }
    return new LocalRemoteFile{path, file};
  }

  ~LocalRemoteFile() {
    CHECK(file_ == nullptr) << "Dtor called before Close(): " << VV(path_);
  }

  // Movable but not copyable.
  LocalRemoteFile(const LocalRemoteFile &) = delete;
  LocalRemoteFile &operator=(const LocalRemoteFile &) = delete;
  LocalRemoteFile(LocalRemoteFile &&) = default;
  LocalRemoteFile &operator=(LocalRemoteFile &&) = default;

  void SetWriteBufSize(size_t size) {
    CHECK(write_buf_ == nullptr) << "SetWriteBufCapacity called twice";
    write_buf_ = std::make_unique<char[]>(size);
    CHECK_EQ(std::setvbuf(file_, write_buf_.get(), _IOFBF, size), 0)
        << VV(path_);
  }

  void Write(const ByteArray &ba) {
    static constexpr auto elt_size = sizeof(ba[0]);
    const auto elts_to_write = ba.size();
    const auto elts_written =
        std::fwrite(ba.data(), elt_size, elts_to_write, file_);
    CHECK_EQ(elts_written, elts_to_write) << VV(path_);
  }

  void Flush() { std::fflush(file_); }

  void Read(ByteArray &ba) {
    // Compute the file size as a difference between the end and start offsets.
    CHECK_EQ(std::fseek(file_, 0, SEEK_END), 0) << VV(path_);
    const auto file_size = std::ftell(file_);
    CHECK_EQ(std::fseek(file_, 0, SEEK_SET), 0) << VV(path_);
    static constexpr auto elt_size = sizeof(ba[0]);
    CHECK_EQ(file_size % elt_size, 0)
        << VV(file_size) << VV(elt_size) << VV(path_);
    const auto elts_to_read = file_size / elt_size;
    ba.resize(elts_to_read);
    const auto elts_read = std::fread(ba.data(), elt_size, elts_to_read, file_);
    CHECK_EQ(elts_read, elts_to_read) << VV(path_);
  }

  void Close() {
    CHECK_EQ(std::fclose(file_), 0) << VV(path_);
    file_ = nullptr;
    write_buf_ = nullptr;
  }

 private:
  LocalRemoteFile(std::string_view path, FILE *file)
      : path_{path}, file_{file} {}

  std::string_view path_;
  FILE *file_;
  std::unique_ptr<char[]> write_buf_;
};

}  // namespace

// NOTE: We use weak symbols for the main API definitions in this source so that
// alternative implementations could easily override them with their own
// versions at link time.

static_assert(ABSL_HAVE_ATTRIBUTE(weak));

ABSL_ATTRIBUTE_WEAK void RemoteMkdir(std::string_view path) {
  CHECK(!path.empty());
  std::error_code error;
  std::filesystem::create_directories(path, error);
  CHECK(!error) << VV(path) << VV(error);
}

// TODO(ussuri): For now, simulate the old behavior, where a failure to open
//  a file returned nullptr. Adjust the clients to expect non-null and use a
//  normal ctor with a CHECK instead of `Create()` here instead.
ABSL_ATTRIBUTE_WEAK absl::Nullable<RemoteFile *> RemoteFileOpen(
    std::string_view path, const char *mode) {
  return LocalRemoteFile::Create(path, mode);
}

ABSL_ATTRIBUTE_WEAK void RemoteFileClose(absl::Nonnull<RemoteFile *> f) {
  auto *file = static_cast<LocalRemoteFile *>(f);
  file->Close();
  delete file;
}

ABSL_ATTRIBUTE_WEAK void RemoteFileSetWriteBufferSize(
    absl::Nonnull<RemoteFile *> f, size_t size) {
  static_cast<LocalRemoteFile *>(f)->SetWriteBufSize(size);
}

ABSL_ATTRIBUTE_WEAK void RemoteFileAppend(absl::Nonnull<RemoteFile *> f,
                                          const ByteArray &ba) {
  static_cast<LocalRemoteFile *>(f)->Write(ba);
}

// Does not need weak attribute as the implementation depends on
// RemoteFileAppend(RemoteFile *, ByteArray).
void RemoteFileAppend(absl::Nonnull<RemoteFile *> f,
                      const std::string &contents) {
  ByteArray contents_ba{contents.cbegin(), contents.cend()};
  RemoteFileAppend(f, contents_ba);
}

ABSL_ATTRIBUTE_WEAK void RemoteFileFlush(absl::Nonnull<RemoteFile *> f) {
  static_cast<LocalRemoteFile *>(f)->Flush();
}

ABSL_ATTRIBUTE_WEAK void RemoteFileRead(absl::Nonnull<RemoteFile *> f,
                                        ByteArray &ba) {
  static_cast<LocalRemoteFile *>(f)->Read(ba);
}

// Does not need weak attribute as the implementation depends on
// RemoteFileRead(RemoteFile *, ByteArray).
void RemoteFileRead(absl::Nonnull<RemoteFile *> f, std::string &contents) {
  ByteArray contents_ba;
  RemoteFileRead(f, contents_ba);
  contents.assign(contents_ba.cbegin(), contents_ba.cend());
}

// Does not need weak attribute as the implementation depends on
// RemoteFileAppend(RemoteFile *, ByteArray).
void RemoteFileSetContents(const std::filesystem::path &path,
                           const ByteArray &contents) {
  auto *file = RemoteFileOpen(path.c_str(), "w");
  CHECK(file != nullptr) << VV(path);
  RemoteFileAppend(file, contents);
  RemoteFileClose(file);
}

// Does not need weak attribute as the implementation depends on
// RemoteFileAppend(RemoteFile *, std::string).
void RemoteFileSetContents(const std::filesystem::path &path,
                           const std::string &contents) {
  auto *file = RemoteFileOpen(path.c_str(), "w");
  CHECK(file != nullptr) << VV(path);
  RemoteFileAppend(file, contents);
  RemoteFileClose(file);
}

// Does not need weak attribute as the implementation depends on
// RemoteFileRead(RemoteFile *, ByteArray).
void RemoteFileGetContents(const std::filesystem::path &path,
                           ByteArray &contents) {
  auto *file = RemoteFileOpen(path.c_str(), "r");
  CHECK(file != nullptr) << VV(path);
  RemoteFileRead(file, contents);
  RemoteFileClose(file);
}

// Does not need weak attribute as the implementation depends on
// RemoteFileRead(RemoteFile *, std::string).
void RemoteFileGetContents(const std::filesystem::path &path,
                           std::string &contents) {
  auto *file = RemoteFileOpen(path.c_str(), "r");
  CHECK(file != nullptr) << VV(path);
  RemoteFileRead(file, contents);
  RemoteFileClose(file);
}

ABSL_ATTRIBUTE_WEAK bool RemotePathExists(std::string_view path) {
  return std::filesystem::exists(path);
}

ABSL_ATTRIBUTE_WEAK int64_t RemoteFileGetSize(std::string_view path) {
  FILE *f = std::fopen(path.data(), "r");
  CHECK(f != nullptr) << VV(path);
  std::fseek(f, 0, SEEK_END);
  const auto sz = std::ftell(f);
  std::fclose(f);
  return sz;
}

namespace {

int HandleGlobError(const char *epath, int eerrno) {
  LOG(FATAL) << "Error while globbing path: " << VV(epath) << VV(eerrno);
  return -1;
}

}  // namespace

ABSL_ATTRIBUTE_WEAK void RemoteGlobMatch(std::string_view glob,
                                         std::vector<std::string> &matches) {
  // See `man glob.3`.
  ::glob_t glob_ret = {};
  CHECK_EQ(
      ::glob(std::string{glob}.c_str(), GLOB_TILDE, HandleGlobError, &glob_ret),
      0)
      << "Error while globbing glob: " << VV(glob);
  for (int i = 0; i < glob_ret.gl_pathc; ++i) {
    matches.emplace_back(glob_ret.gl_pathv[i]);
  }
  ::globfree(&glob_ret);
}

ABSL_ATTRIBUTE_WEAK std::vector<std::string> RemoteListFiles(
    std::string_view path, bool recursively) {
  if (!std::filesystem::exists(path)) return {};
  auto list_files = [](auto dir_iter) {
    std::vector<std::string> ret;
    for (const auto &entry : dir_iter) {
      if (entry.is_directory()) continue;
      ret.push_back(entry.path());
    }
    return ret;
  };
  return recursively
             ? list_files(std::filesystem::recursive_directory_iterator(path))
             : list_files(std::filesystem::directory_iterator(path));
}

ABSL_ATTRIBUTE_WEAK void RemotePathRename(std::string_view from,
                                          std::string_view to) {
  std::error_code error;
  std::filesystem::rename(from, to, error);
  CHECK(!error) << VV(from) << VV(to) << VV(error);
}

ABSL_ATTRIBUTE_WEAK void RemotePathDelete(std::string_view path,
                                          bool recursively) {
  std::error_code error;
  if (recursively) {
    std::filesystem::remove_all(path, error);
  } else {
    std::filesystem::remove(path, error);
  }
  CHECK(!error) << VV(path) << VV(error);
}

#ifndef CENTIPEDE_DISABLE_RIEGELI
ABSL_ATTRIBUTE_WEAK std::unique_ptr<riegeli::Reader> CreateRiegeliFileReader(
    std::string_view file_path) {
  return std::make_unique<riegeli::FdReader<>>(file_path);
}

ABSL_ATTRIBUTE_WEAK std::unique_ptr<riegeli::Writer> CreateRiegeliFileWriter(
    std::string_view file_path, bool append) {
  return std::make_unique<riegeli::FdWriter<>>(
      file_path, riegeli::FdWriterBase::Options().set_append(append));
}
#endif  // CENTIPEDE_DISABLE_RIEGELI

}  // namespace centipede
