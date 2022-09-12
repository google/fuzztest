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

std::optional<std::string> ReadFile(std::string_view file);

struct FilePathAndData {
  std::string path;
  std::string data;
};
std::vector<FilePathAndData> ReadFileOrDirectory(std::string_view file_or_dir);

}  // namespace fuzztest::internal

#endif  // FUZZTEST_FUZZTEST_INTERNAL_IO_H_
