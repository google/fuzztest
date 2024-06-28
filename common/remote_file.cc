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

// Implementation of the function from remote_file.h that don't directly depend
// a specific file system.

#include "./common/remote_file.h"

#include <filesystem>  // NOLINT
#include <string>

#include "absl/base/nullability.h"
#include "absl/log/check.h"
#include "./common/defs.h"
#include "./common/logging.h"

namespace centipede {

void RemoteFileAppend(absl::Nonnull<RemoteFile *> f,
                      const std::string &contents) {
  ByteArray contents_ba{contents.cbegin(), contents.cend()};
  RemoteFileAppend(f, contents_ba);
}

void RemoteFileRead(absl::Nonnull<RemoteFile *> f, std::string &contents) {
  ByteArray contents_ba;
  RemoteFileRead(f, contents_ba);
  contents.assign(contents_ba.cbegin(), contents_ba.cend());
}

void RemoteFileSetContents(const std::filesystem::path &path,
                           const ByteArray &contents) {
  auto *file = RemoteFileOpen(path.string(), "w");
  CHECK(file != nullptr) << VV(path);
  RemoteFileAppend(file, contents);
  RemoteFileClose(file);
}

void RemoteFileSetContents(const std::filesystem::path &path,
                           const std::string &contents) {
  auto *file = RemoteFileOpen(path.string(), "w");
  CHECK(file != nullptr) << VV(path);
  RemoteFileAppend(file, contents);
  RemoteFileClose(file);
}

void RemoteFileGetContents(const std::filesystem::path &path,
                           ByteArray &contents) {
  auto *file = RemoteFileOpen(path.string(), "r");
  CHECK(file != nullptr) << VV(path);
  RemoteFileRead(file, contents);
  RemoteFileClose(file);
}

void RemoteFileGetContents(const std::filesystem::path &path,
                           std::string &contents) {
  auto *file = RemoteFileOpen(path.string(), "r");
  CHECK(file != nullptr) << VV(path);
  RemoteFileRead(file, contents);
  RemoteFileClose(file);
}

}  // namespace centipede
