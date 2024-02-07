// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./fuzztest/internal/io.h"

#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/hash/hash.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "./centipede/remote_file.h"
#include "./fuzztest/internal/logging.h"

#if defined(__APPLE__)
#if (defined(__MAC_OS_X_VERSION_MIN_REQUIRED) &&       \
     __MAC_OS_X_VERSION_MIN_REQUIRED < __MAC_10_15) || \
    (defined(__IPHONE_OS_VERSION_MIN_REQUIRED) &&      \
     __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_13_0)
// std::filesystem requires macOS 10.15+ or iOS 13+.
// Just stub out these functions.
#define FUZZTEST_STUB_FILESYSTEM
#endif
#endif

namespace fuzztest::internal {

#if defined(FUZZTEST_STUB_FILESYSTEM)

bool WriteFile(absl::string_view path, absl::string_view contents) {
  FUZZTEST_INTERNAL_CHECK(false, "Filesystem API not supported in iOS/MacOS");
}

std::optional<std::string> ReadFile(absl::string_view path) {
  FUZZTEST_INTERNAL_CHECK(false, "Filesystem API not supported in iOS/MacOS");
}

bool IsDirectory(absl::string_view path) {
  FUZZTEST_INTERNAL_CHECK(false, "Filesystem API not supported in iOS/MacOS");
}

bool CreateDirectory(absl::string_view path) {
  FUZZTEST_INTERNAL_CHECK(false, "Filesystem API not supported in iOS/MacOS");
}

std::vector<std::string> ListDirectory(absl::string_view path) {
  FUZZTEST_INTERNAL_CHECK(false, "Filesystem API not supported in iOS/MacOS");
}

std::vector<std::string> ListDirectoryRecursively(absl::string_view path) {
  FUZZTEST_INTERNAL_CHECK(false, "Filesystem API not supported in iOS/MacOS");
}

#else  // FUZZTEST_STUB_FILESYSTEM

bool WriteFile(absl::string_view path, absl::string_view contents) {
  // Just in case the directory does not currently exist.
  if (!CreateDirectory(Dirname(path))) {
    absl::FPrintF(GetStderr(), "[!] %s:%d: Couldn't create directory: %s\n",
                  __FILE__, __LINE__, path);
    return false;
  }
  centipede::RemoteFileSetContents(path, std::string(contents));
  return true;
}

std::optional<std::string> ReadFile(absl::string_view path) {
  std::string contents;
  if (!centipede::RemotePathExists(path)) {
    absl::FPrintF(GetStderr(), "[!] %s:%d: File doesn't exist: %s\n", __FILE__,
                  __LINE__, path);
    return std::nullopt;
  }
  centipede::RemoteFileGetContents(path, contents);
  return contents;
}

bool IsDirectory(absl::string_view path) {
  return centipede::RemotePathIsDirectory(path);
}

bool CreateDirectory(absl::string_view path) {
  centipede::RemoteMkdir(path);
  return true;
}

std::vector<std::string> ListDirectory(absl::string_view path) {
  return centipede::RemoteListDirectory(path);
}

std::vector<std::string> ListDirectoryRecursively(absl::string_view path) {
  return centipede::RemoteListFilesRecursively(path);
}

#endif  // FUZZTEST_STUB_FILESYSTEM

std::string WriteDataToDir(absl::string_view data, absl::string_view outdir) {
  std::string filename(outdir);
  if (filename.back() != '/') filename += '/';
  absl::StrAppendFormat(&filename, "%016x",
                        absl::Hash<absl::string_view>{}(data));
  if (!WriteFile(filename, data)) return "";
  return filename;
}

std::vector<FilePathAndData> ReadFileOrDirectory(
    absl::string_view file_or_dir) {
  std::vector<FilePathAndData> out;

  const auto try_append_file = [&](std::string path) {
    std::optional<std::string> contents = ReadFile(path);
    if (contents.has_value()) {
      out.push_back(FilePathAndData{std::move(path), *std::move(contents)});
    }
  };
  if (IsDirectory(file_or_dir)) {
    for (const auto& path : ListDirectoryRecursively(file_or_dir)) {
      if (!IsDirectory(path)) {
        try_append_file(path);
      }
    }
  } else {
    try_append_file(std::string(file_or_dir));
  }
  return out;
}

absl::string_view Dirname(absl::string_view filename) {
  auto last_slash_pos = filename.find_last_of("/\\");

  return last_slash_pos == absl::string_view::npos
             ? filename
             : filename.substr(0, last_slash_pos);
}

absl::string_view Basename(absl::string_view filename) {
  auto last_slash_pos = filename.find_last_of("/\\");

  return last_slash_pos == absl::string_view::npos
             ? filename
             : filename.substr(last_slash_pos + 1);
}

std::vector<std::tuple<std::string>> ReadFilesFromDirectory(
    absl::string_view dir) {
  std::vector<FilePathAndData> files =
      ReadFileOrDirectory({dir.data(), dir.size()});

  std::vector<std::tuple<std::string>> out;
  out.reserve(files.size());

  for (const FilePathAndData& file : files) {
    out.push_back(std::make_tuple(file.data));
  }

  return out;
}

}  // namespace fuzztest::internal
