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

#ifndef FUZZTEST_FUZZTEST_INTERNAL_IO_H_
#define FUZZTEST_FUZZTEST_INTERNAL_IO_H_

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace fuzztest::internal {

bool WriteFile(std::string_view filename, std::string_view contents);

// Write `data` to its hash-based filename in `dir`. Returns the `dir`-appended
// path to the file.
std::string WriteDataToDir(std::string_view data, std::string_view dir);

// Reads `file` and returns its content. If `file` is not a regular file or
// reading it fails, returns `std::nullopt`.
std::optional<std::string> ReadFile(std::string_view file);

struct FilePathAndData {
  std::string path;
  std::string data;
};

// If `file_or_dir` is a directory, returns a list of its files' paths and
// contents. If `file_or_dir` is a file, returns a singleton list with its path
// and content. In all other cases, returns an empty list.
std::vector<FilePathAndData> ReadFileOrDirectory(std::string_view file_or_dir);

// Returns a list of top-level paths in `dir`. If `dir` is not a directory,
// returns an empty list.
std::vector<std::string> ListDirectory(std::string_view dir);

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_IO_H_
