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

#include <filesystem>  // NOLINT
#include <memory>
#include <string>
#include <string_view>
#include <system_error>  // NOLINT
#include <vector>

#include "absl/base/attributes.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "./centipede/logging.h"
#include "riegeli/bytes/fd_reader.h"
#include "riegeli/bytes/fd_writer.h"
#include "riegeli/bytes/reader.h"
#include "riegeli/bytes/writer.h"

namespace centipede {

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

ABSL_ATTRIBUTE_WEAK bool RemotePathExists(std::string_view path) {
  return std::filesystem::exists(path);
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

ABSL_ATTRIBUTE_WEAK std::vector<std::string> RemoteListFilesRecursively(
    std::string_view path) {
  if (!std::filesystem::exists(path)) return {};
  std::vector<std::string> ret;
  for (const auto &entry :
       std::filesystem::recursive_directory_iterator(path)) {
    if (entry.is_directory()) continue;
    ret.push_back(entry.path());
  }
  return ret;
}

ABSL_ATTRIBUTE_WEAK std::unique_ptr<riegeli::Reader> CreateRiegeliFileReader(
    std::string_view file_path) {
  return std::make_unique<riegeli::FdReader<>>(file_path);
}

ABSL_ATTRIBUTE_WEAK std::unique_ptr<riegeli::Writer> CreateRiegeliFileWriter(
    std::string_view file_path, bool append) {
  return std::make_unique<riegeli::FdWriter<>>(
      file_path, riegeli::FdWriterBase::Options().set_append(append));
}

}  // namespace centipede
