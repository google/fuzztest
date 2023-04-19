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

#include <cstdio>
#include <filesystem>  // NOLINT
#include <string_view>

#include "absl/base/attributes.h"
#include "./centipede/defs.h"
#include "./centipede/logging.h"

namespace centipede {

// NOTE: We use weak symbols for the main API definitions in this source so that
// alternative implementations could easily override them with their own
// versions at link time.

static_assert(ABSL_HAVE_ATTRIBUTE(weak));

ABSL_ATTRIBUTE_WEAK void RemoteMkdir(std::string_view path) {
  CHECK(!path.empty());
  std::filesystem::create_directory(path);
}

ABSL_ATTRIBUTE_WEAK RemoteFile *RemoteFileOpen(std::string_view path,
                                               const char *mode) {
  CHECK(!path.empty());
  FILE *f = std::fopen(path.data(), mode);
  return reinterpret_cast<RemoteFile *>(f);
}

ABSL_ATTRIBUTE_WEAK void RemoteFileClose(RemoteFile *f) {
  CHECK(f != nullptr);
  std::fclose(reinterpret_cast<FILE *>(f));
}

ABSL_ATTRIBUTE_WEAK void RemoteFileAppend(RemoteFile *f, const ByteArray &ba) {
  CHECK(f != nullptr);
  auto *file = reinterpret_cast<FILE *>(f);
  constexpr auto elt_size = sizeof(ba[0]);
  const auto elts_to_write = ba.size();
  const auto elts_written =
      std::fwrite(ba.data(), elt_size, elts_to_write, file);
  CHECK_EQ(elts_written, elts_to_write);
}

// Does not need weak attribute as the implementation depends on
// RemoteFileAppend(RemoteFile *, ByteArray).
void RemoteFileAppend(RemoteFile *f, const std::string &contents) {
  CHECK(f != nullptr);
  ByteArray contents_ba{contents.cbegin(), contents.cend()};
  RemoteFileAppend(f, contents_ba);
}

ABSL_ATTRIBUTE_WEAK void RemoteFileRead(RemoteFile *f, ByteArray &ba) {
  CHECK(f != nullptr);
  auto *file = reinterpret_cast<FILE *>(f);
  std::fseek(file, 0, SEEK_END);  // seek to end
  const auto file_size = std::ftell(file);
  std::fseek(file, 0, SEEK_SET);  // seek back to start
  constexpr auto elt_size = sizeof(ba[0]);
  CHECK_EQ(file_size % elt_size, 0) << VV(file_size) << VV(elt_size);
  const auto elts_to_read = file_size / elt_size;
  ba.resize(elts_to_read);
  const auto elts_read = std::fread(ba.data(), elt_size, elts_to_read, file);
  CHECK_EQ(elts_read, elts_to_read);
}

// Does not need weak attribute as the implementation depends on
// RemoteFileRead(RemoteFile *, ByteArray).
void RemoteFileRead(RemoteFile *f, std::string &contents) {
  CHECK(f != nullptr);
  ByteArray contents_ba;
  RemoteFileRead(f, contents_ba);
  contents.assign(contents_ba.cbegin(), contents_ba.cend());
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
// RemoteFileRead(RemoteFile *, std::string).
void RemoteFileGetContents(const std::filesystem::path &path,
                           std::string &contents) {
  auto *file = RemoteFileOpen(path.c_str(), "r");
  CHECK(file != nullptr) << VV(path);
  RemoteFileRead(file, contents);
  RemoteFileClose(file);
}

}  // namespace centipede
