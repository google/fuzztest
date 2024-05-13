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

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
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

// TODO(lszekeres): Return absl::Status instead of bool for these.

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

#else

bool WriteFileStd(absl::string_view path, absl::string_view contents) {
  const std::filesystem::path fs_path{
      std::string_view{path.data(), path.size()}};

  // Just in case the directory does not currently exist.
  // If it does, this is a noop.
  CreateDirectory(fs_path.parent_path().string());

  std::ofstream file(fs_path);
  file << contents;
  file.close();
  if (!file.good()) {
    absl::FPrintF(GetStderr(), "[!] %s:%d: Error writing %s: (%d) %s\n",
                  __FILE__, __LINE__, path, errno, strerror(errno));
  }
  return !file.fail();
}

std::optional<std::string> ReadFileStd(absl::string_view path) {
  const std::filesystem::path fs_path{
      std::string_view{path.data(), path.size()}};

  std::ifstream stream(fs_path);
  if (!stream.good()) {
    // Using stderr instead of GetStderr() to avoid initialization-order-fiasco
    // when reading files at static init time with
    // `.WithSeeds(fuzztest::ReadFilesFromDirectory(...))`.
    absl::FPrintF(stderr, "[!] %s:%d: Error reading %s: (%d) %s\n", __FILE__,
                  __LINE__, path, errno, strerror(errno));
    return std::nullopt;
  }
  std::stringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

bool IsDirectoryStd(absl::string_view path) {
  const std::filesystem::path fs_path{
      std::string_view{path.data(), path.size()}};

  return std::filesystem::is_directory(fs_path);
}

bool CreateDirectoryStd(absl::string_view path) {
  const std::filesystem::path fs_path{
      std::string_view{path.data(), path.size()}};

  return std::filesystem::create_directories(fs_path);
}

std::vector<std::string> ListDirectoryStd(absl::string_view path) {
  std::vector<std::string> output_paths;

  const std::filesystem::path fs_path{
      std::string_view{path.data(), path.size()}};
  if (!std::filesystem::is_directory(fs_path)) return output_paths;
  for (const auto& entry : std::filesystem::directory_iterator(fs_path)) {
    output_paths.push_back(entry.path().string());
  }
  return output_paths;
}

std::vector<std::string> ListDirectoryRecursivelyStd(absl::string_view path) {
  std::vector<std::string> output_paths;

  const std::filesystem::path fs_path{
      std::string_view{path.data(), path.size()}};
  for (const auto& entry :
       std::filesystem::recursive_directory_iterator(fs_path)) {
    output_paths.push_back(entry.path().string());
  }
  return output_paths;
}

bool WriteFile(absl::string_view path, absl::string_view contents) {
  return WriteFileStd(path, contents);
}

std::optional<std::string> ReadFile(absl::string_view path) {
  return ReadFileStd(path);
}

bool IsDirectory(absl::string_view path) { return IsDirectoryStd(path); }

bool CreateDirectory(absl::string_view path) {
  return CreateDirectoryStd(path);
}

std::vector<std::string> ListDirectory(absl::string_view path) {
  return ListDirectoryStd(path);
}

std::vector<std::string> ListDirectoryRecursively(absl::string_view path) {
  return ListDirectoryRecursivelyStd(path);
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
    std::optional<std::string> contents = ReadFileStd(path);
    if (contents.has_value()) {
      out.push_back(FilePathAndData{std::move(path), *std::move(contents)});
    }
  };
  if (IsDirectoryStd(file_or_dir)) {
    for (const auto& path : ListDirectoryRecursivelyStd(file_or_dir)) {
      if (!IsDirectoryStd(path)) {
        try_append_file(path);
      }
    }
  } else {
    try_append_file(std::string(file_or_dir));
  }
  return out;
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
