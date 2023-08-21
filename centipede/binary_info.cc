// Copyright 2023 The Centipede Authors.
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

#include "./centipede/binary_info.h"

#include <filesystem>  // NOLINT
#include <string>
#include <string_view>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/str_split.h"
#include "./centipede/control_flow.h"

namespace centipede {

void BinaryInfo::InitializeFromSanCovBinary(
    std::string_view binary_path_with_args, std::string_view objdump_path,
    std::string_view symbolizer_path, std::string_view tmp_dir_path) {
  // Compute names for temp files.
  const std::filesystem::path tmp_dir = tmp_dir_path;
  CHECK(std::filesystem::exists(tmp_dir) &&
        std::filesystem::is_directory(tmp_dir));
  const std::string tmp_file_path1 = tmp_dir / "binary_info_tmp1";
  const std::string tmp_file_path2 = tmp_dir / "binary_info_tmp2";
  LOG(INFO) << __func__ << ": tmp_dir: " << tmp_dir;

  // Load PC Table.
  pc_table =
      GetPcTableFromBinary(binary_path_with_args, objdump_path, tmp_file_path1,
                           &uses_legacy_trace_pc_instrumentation);

  // Load CF Table.
  cf_table = GetCfTableFromBinary(binary_path_with_args, tmp_file_path1);

  // Load symbols, if there is a PC table.
  if (!pc_table.empty()) {
    const std::vector<std::string> args =
        absl::StrSplit(binary_path_with_args, absl::ByAnyChar{" \t\n"},
                       absl::SkipWhitespace{});
    CHECK(!args.empty());
    symbols.GetSymbolsFromBinary(pc_table, /*binary_path=*/args[0],
                                 symbolizer_path, tmp_file_path1,
                                 tmp_file_path2);
  }

  // Remove temp files.
  std::filesystem::remove(tmp_file_path1);
  std::filesystem::remove(tmp_file_path2);
}

}  // namespace centipede
