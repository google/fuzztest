// Copyright 2025 The Centipede Authors.
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

#include "./common/crashing_input_filename.h"

#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "./fuzztest/internal/io.h"

namespace fuzztest::internal {

absl::StatusOr<InputFileComponents> ParseCrashingInputFilename(
    std::string_view input_file_path) {
  absl::string_view file_name = Basename(
      absl::string_view{input_file_path.data(), input_file_path.size()});
  std::vector<std::string> parts = absl::StrSplit(file_name, '-');
  if (parts.size() == 1) {
    // Old format where the input file name is both the bug ID and the input
    // signature.
    return InputFileComponents{
        /*bug_id=*/parts[0],
        /*crash_signature=*/"",
        /*input_signature=*/parts[0],
    };
  }
  if (parts.size() < 3) {
    return absl::InvalidArgumentError(
        absl::StrCat("Input file name not in the format of "
                     "<bug_id>-<crash_signature>-<input_signature>: ",
                     file_name));
  }
  return InputFileComponents{
      /*bug_id=*/absl::StrJoin(parts.begin(), parts.end() - 2, "-"),
      /*crash_signature=*/std::move(parts[parts.size() - 2]),
      /*input_signature=*/std::move(parts[parts.size() - 1]),
  };
}

}  // namespace fuzztest::internal
