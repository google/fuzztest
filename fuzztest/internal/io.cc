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
#include <utility>
#include <vector>

#include "absl/hash/hash.h"
#include "absl/strings/str_format.h"
#include "./fuzztest/internal/logging.h"

#if defined(__APPLE__)
#if (defined(__MAC_OS_X_VERSION_MIN_REQUIRED) &&       \
     __MAC_OS_X_VERSION_MIN_REQUIRED < __MAC_10_15) || \
    (defined(__IPHONE_OS_VERSION_MIN_REQUIRED) &&      \
     __IPHONE_OS_VERSION_MIN_REQUIRED < __IPHONE_13_0)
// std::filesystem requires macOS 10.15+ or iOS 13+.
// Just stub out these functions.
#define STUB_FILESYSTEM
#endif
#endif

namespace fuzztest::internal {

#if defined(STUB_FILESYSTEM)

bool WriteFile(std::string_view filename, std::string_view contents) {
  FUZZTEST_INTERNAL_CHECK(false, "Can't replay in iOS/MacOS");
}

std::string WriteDataToDir(std::string_view data, std::string_view dir) {
  FUZZTEST_INTERNAL_CHECK(false, "Can't replay in iOS/MacOS");
}

std::vector<FilePathAndData> ReadFileOrDirectory(std::string_view file_or_dir) {
  FUZZTEST_INTERNAL_CHECK(false, "Can't replay in iOS/MacOS");
}

std::optional<std::string> ReadFile(std::string_view file) {
  FUZZTEST_INTERNAL_CHECK(false, "Can't replay in iOS/MacOS");
}

std::vector<std::string> ListDirectory(std::string_view dir) {
  FUZZTEST_INTERNAL_CHECK(false, "Can't replay in iOS/MacOS");
}

#else  // defined(__APPLE__)

bool WriteFile(std::string_view filename, std::string_view contents) {
  // Just in case the directory does not currently exist.
  // If it does, this is a noop.
  std::filesystem::create_directories(
      std::filesystem::path(filename).parent_path());

  std::ofstream file;
  file.open(std::string(filename));
  file << contents;
  file.close();
  if (!file.good()) {
    absl::FPrintF(GetStderr(), "%s:%d: Error writing %s: (%d) %s\n", __FILE__,
                  __LINE__, filename.data(), errno, strerror(errno));
  }
  return !file.fail();
}

std::string WriteDataToDir(std::string_view data, std::string_view outdir) {
  std::string filename(outdir);
  if (filename.back() != '/') filename += '/';
  absl::StrAppendFormat(&filename, "%016x",
                        absl::Hash<std::string_view>{}(data));
  if (!WriteFile(filename, data)) return "";
  return filename;
}

std::optional<std::string> ReadFile(std::string_view file) {
  if (!std::filesystem::is_regular_file(file)) return std::nullopt;
  std::ifstream stream(file.data());
  if (!stream.good()) {
    absl::FPrintF(stderr, "%s:%d: Error reading %s: (%d) %s\n", __FILE__,
                  __LINE__, file, errno, strerror(errno));
    return std::nullopt;
  }
  std::stringstream buffer;
  buffer << stream.rdbuf();
  return buffer.str();
}

std::vector<FilePathAndData> ReadFileOrDirectory(std::string_view file_or_dir) {
  std::vector<FilePathAndData> out;
  const auto try_append_file = [&](std::string path) {
    std::optional<std::string> data = ReadFile(path);
    if (data.has_value()) {
      out.push_back(FilePathAndData{std::move(path), *std::move(data)});
    }
  };
  if (std::filesystem::is_directory(file_or_dir)) {
    for (const auto& entry :
         std::filesystem::recursive_directory_iterator(file_or_dir)) {
      try_append_file(entry.path().string());
    }
  } else {
    try_append_file(std::string(file_or_dir));
  }
  return out;
}

std::vector<std::string> ListDirectory(std::string_view dir) {
  std::vector<std::string> out;
  if (!std::filesystem::is_directory(dir)) return out;
  for (const auto& entry : std::filesystem::directory_iterator(dir)) {
    out.push_back(entry.path().string());
  }
  return out;
}

#endif  // defined(STUB_FILESYSTEM)

}  // namespace fuzztest::internal
