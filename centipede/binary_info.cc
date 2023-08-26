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

#include <cstdlib>
#include <filesystem>  // NOLINT
#include <string>
#include <string_view>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "./centipede/command.h"
#include "./centipede/control_flow.h"
#include "./centipede/util.h"

namespace centipede {

void BinaryInfo::InitializeFromSanCovBinary(
    std::string_view binary_path_with_args, std::string_view objdump_path,
    std::string_view symbolizer_path, std::string_view tmp_dir_path) {
  // Compute names for temp files.
  const std::filesystem::path tmp_dir = tmp_dir_path;
  CHECK(std::filesystem::exists(tmp_dir) &&
        std::filesystem::is_directory(tmp_dir));
  ScopedFile pc_table_path(tmp_dir_path, "pc_table_tmp");
  ScopedFile cf_table_path(tmp_dir_path, "cf_table_tmp");
  ScopedFile dso_table_path(tmp_dir_path, "dso_table_tmp");
  ScopedFile log_path(tmp_dir_path, "binary_info_log_tmp");
  LOG(INFO) << __func__ << ": tmp_dir: " << tmp_dir;

  Command cmd(
      binary_path_with_args, {},
      {absl::StrCat("CENTIPEDE_RUNNER_FLAGS=:dump_binary_info:arg1=",
                    pc_table_path.path(), ":arg2=", cf_table_path.path(),
                    ":arg3=", dso_table_path.path(), ":")},
      log_path.path());
  int exit_code = cmd.Execute();
  if (exit_code != EXIT_SUCCESS) {
    LOG(INFO) << __func__ << ": exit_code: " << exit_code;
  }

  // Load PC Table.
  pc_table = ReadPcTableFromFile(pc_table_path.path());
  if (pc_table.empty()) {
    // Fallback to GetPcTableFromBinaryWithTracePC().
    LOG(WARNING)
        << "Failed to dump PC table directly from binary using linked-in "
           "runner; see target execution logs above; falling back to legacy PC "
           "table extraction using trace-pc and objdump";
    pc_table = GetPcTableFromBinaryWithTracePC(
        binary_path_with_args, objdump_path, pc_table_path.path());
    if (pc_table.empty()) {
      LOG(ERROR) << "Failed to extract PC table from binary using objdump; see "
                    "objdump execution logs above";
    }
    uses_legacy_trace_pc_instrumentation = true;
  } else {
    uses_legacy_trace_pc_instrumentation = false;
  }

  // Load CF Table.
  if (std::filesystem::exists(cf_table_path.path()))
    cf_table = ReadCfTableFromFile(cf_table_path.path());

  // TODO(b/295881936): load the DSO Table.

  // Load symbols, if there is a PC table.
  if (!pc_table.empty()) {
    const std::vector<std::string> args =
        absl::StrSplit(binary_path_with_args, absl::ByAnyChar{" \t\n"},
                       absl::SkipWhitespace{});
    CHECK(!args.empty());
    ScopedFile sym_tmp1_path(tmp_dir_path, "symbols_tmp1");
    ScopedFile sym_tmp2_path(tmp_dir_path, "symbols_tmp2");
    symbols.GetSymbolsFromBinary(pc_table, /*binary_path=*/args[0],
                                 symbolizer_path, sym_tmp1_path.path(),
                                 sym_tmp2_path.path());
  }
}

}  // namespace centipede
