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
#include <vector>

#include "absl/strings/string_view.h"

namespace fuzztest::internal {

// Writes `contents` to the file at `path`.  Returns true on success, false
// otherwise.
bool WriteFile(absl::string_view path, absl::string_view contents);

// Returns the contents of the file at `path` or std::nullopt on failure.
std::optional<std::string> ReadFile(absl::string_view path);

// Returns true if `path` is a directory, false otherwise.
bool IsDirectory(absl::string_view path);

// Creates directory at `path`, *recursively* creating parent directories if
// necessary. Returns true on success, false otherwise.
bool CreateDirectory(absl::string_view path);

// Returns a list of top-level paths under `path`. If `path` is not a directory,
// returns an empty list.
std::vector<std::string> ListDirectory(absl::string_view path);

// Returns all paths under `path` *recursively*. If `path` is not a directory,
// returns an empty list.
std::vector<std::string> ListDirectoryRecursively(absl::string_view path);

// Write `data` to its hash-based filename in `dir`. Returns the `dir`-appended
// path to the file.
std::string WriteDataToDir(absl::string_view data, absl::string_view dir);

struct FilePathAndData {
  std::string path;
  std::string data;
};

// If `file_or_dir` is a directory, returns a list of its files' paths and
// contents *recursively*. If `file_or_dir` is a file, returns a singleton list
// with its path and content. In all other cases, returns an empty list.
std::vector<FilePathAndData> ReadFileOrDirectory(absl::string_view file_or_dir);

// Returns the basename of `filename`.
absl::string_view Basename(absl::string_view filename);

// Reads files as strings from the directory `dir` and returns a vector usable
// by .WithSeeds().
std::vector<std::tuple<std::string>> ReadFilesFromDirectory(
    absl::string_view dir);

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_IO_H_
