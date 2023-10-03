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

#include "./centipede/symbol_table.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <ostream>
#include <string>
#include <string_view>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/strip.h"
#include "absl/types/span.h"
#include "./centipede/command.h"
#include "./centipede/control_flow.h"
#include "./centipede/logging.h"
#include "./centipede/pc_info.h"
#include "./centipede/util.h"

namespace centipede {

bool SymbolTable::Entry::operator==(const Entry &other) const {
  return this->func == other.func && this->file_line_col == other.file_line_col;
}

bool SymbolTable::operator==(const SymbolTable &other) const {
  return this->entries_ == other.entries_;
}

void SymbolTable::ReadFromLLVMSymbolizer(std::istream &in) {
  // We remove some useless file prefixes for better human readability.
  const std::string_view file_prefixes_to_remove[] = {"/proc/self/cwd/", "./"};
  while (in) {
    // We (mostly) blindly trust the input format is correct.
    std::string func, file, empty;
    std::getline(in, func);
    std::getline(in, file);
    std::getline(in, empty);
    CHECK(empty.empty()) << "Unexpected symbolizer output format: " << VV(func)
                         << VV(file) << VV(empty);
    if (!in) break;
    for (auto &bad_prefix : file_prefixes_to_remove) {
      file = absl::StripPrefix(file, bad_prefix);
    }
    AddEntry(func, file);
  }
}

void SymbolTable::WriteToLLVMSymbolizer(std::ostream &out) {
  for (const Entry &entry : entries_) {
    out << entry.func << std::endl;
    out << entry.file_line_col << std::endl;
    out << std::endl;
  }
}

void SymbolTable::GetSymbolsFromOneDso(absl::Span<const PCInfo> pc_infos,
                                       std::string_view dso_path,
                                       std::string_view symbolizer_path,
                                       std::string_view tmp_path1,
                                       std::string_view tmp_path2) {
  auto pcs_path(tmp_path1);
  auto symbols_path(tmp_path2);
  // Create the input file (one PC per line).
  std::string pcs_string;
  for (const auto &pc_info : pc_infos) {
    absl::StrAppend(&pcs_string, "0x", absl::Hex(pc_info.pc), "\n");
  }
  WriteToLocalFile(pcs_path, pcs_string);
  // Run the symbolizer.
  Command cmd(symbolizer_path,
              {
                  "--no-inlines",
                  "-e",
                  std::string(dso_path),
                  "<",
                  std::string(pcs_path),
              },
              /*env=*/{}, symbols_path);

  LOG(INFO) << "Symbolizing " << pc_infos.size() << " PCs from "
            << std::filesystem::path(dso_path).filename();

  int exit_code = cmd.Execute();
  if (exit_code != EXIT_SUCCESS) {
    LOG(ERROR) << "system() failed: " << VV(cmd.ToString()) << VV(exit_code);
    return;
  }
  // Get and process the symbolizer output.
  std::ifstream symbolizer_output(std::string{symbols_path});
  size_t old_size = size();
  ReadFromLLVMSymbolizer(symbolizer_output);
  std::filesystem::remove(pcs_path);
  std::filesystem::remove(symbols_path);
  size_t new_size = size();
  size_t added_size = new_size - old_size;
  if (added_size != pc_infos.size())
    LOG(ERROR) << "Symbolization failed: debug symbols will not be used";
}

void SymbolTable::GetSymbolsFromBinary(const PCTable &pc_table,
                                       const DsoTable &dso_table,
                                       std::string_view symbolizer_path,
                                       std::string_view tmp_path1,
                                       std::string_view tmp_path2) {
  // NOTE: --symbolizer_path=/dev/null is a somewhat expected alternative to
  // "" that users might pass.
  if (symbolizer_path.empty() || symbolizer_path == "/dev/null") {
    LOG(WARNING) << "Symbolizer unspecified: debug symbols will not be used";
    SetAllToUnknown(pc_table.size());
    return;
  }

  LOG(INFO) << "Symbolizing " << dso_table.size() << " instrumented DSOs";

  // Iterate all DSOs, symbolize their respective PCs.
  size_t pc_idx_begin = 0;
  for (const auto &dso_info : dso_table) {
    CHECK_LE(pc_idx_begin + dso_info.num_instrumented_pcs, pc_table.size());
    const absl::Span<const PCInfo> pc_infos = {pc_table.data() + pc_idx_begin,
                                               dso_info.num_instrumented_pcs};
    GetSymbolsFromOneDso(pc_infos, dso_info.path, symbolizer_path, tmp_path1,
                         tmp_path2);
    pc_idx_begin += dso_info.num_instrumented_pcs;
  }
  CHECK_EQ(pc_idx_begin, pc_table.size());

  if (size() != pc_table.size()) {
    // Something went wrong. Set symbols to unknown so the sizes of pc_table and
    // symbols always match.
    SetAllToUnknown(pc_table.size());
  }
}

void SymbolTable::SetAllToUnknown(size_t size) {
  entries_.resize(size);
  for (auto &entry : entries_) {
    entry = {"?", "?"};
  }
}

}  // namespace centipede
