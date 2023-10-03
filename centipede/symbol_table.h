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

#ifndef THIRD_PARTY_CENTIPEDE_SYMBOL_TABLE_H_
#define THIRD_PARTY_CENTIPEDE_SYMBOL_TABLE_H_

#include <cstddef>
#include <istream>
#include <ostream>
#include <string>
#include <string_view>
#include <vector>

#include "absl/types/span.h"
#include "./centipede/control_flow.h"
#include "./centipede/pc_info.h"

namespace centipede {

// Maps integer indices in [0, size) to debug symbols:
// function names, file names, line numbers, column numbers.
class SymbolTable {
 public:
  bool operator==(const SymbolTable &other) const;
  // Reads the symbols from a stream produced by `llvm-symbolizer --no-inlines`.
  // https://llvm.org/docs/CommandGuide/llvm-symbolizer.html.
  // The input consists of tuples of 3 lines each:
  //   FunctionName
  //   SourceCodeLocation
  //   <empty line>
  // If called multiple times, this function will append symbols to `this`.
  void ReadFromLLVMSymbolizer(std::istream &in);

  // Writes the contents of `this` to `path` in the same format as read by
  // `ReadFromLLVMSymbolizer`.
  void WriteToLLVMSymbolizer(std::ostream &out);

  // Invokes `symbolizer_path --no-inlines` on all binaries from `dso_table`,
  // pipes through it all PCs in pc_table that correspond to each of the
  // binaries and calls ReadFromLLVMSymbolizer() on the output.
  // Possibly uses files `tmp_path1` and `tmp_path2` for temporary storage.
  void GetSymbolsFromBinary(const PCTable &pc_table, const DsoTable &dso_table,
                            std::string_view symbolizer_path,
                            std::string_view tmp_path1,
                            std::string_view tmp_path2);

  // Helper for GetSymbolsFromBinary: symbolizes `pc_infos` for `dso_path`.
  void GetSymbolsFromOneDso(absl::Span<const PCInfo> pc_infos,
                            std::string_view dso_path,
                            std::string_view symbolizer_path,
                            std::string_view tmp_path1,
                            std::string_view tmp_path2);

  // Sets the table to `size` symbols all of which are unknown.
  void SetAllToUnknown(size_t size);

  // Returns the number of symbol entries.
  size_t size() const { return entries_.size(); }

  // Returns "FunctionName" for idx-th entry.
  const std::string &func(size_t idx) const { return entries_[idx].func; }

  // Returns source code location for idx-th entry,
  const std::string &location(size_t idx) const {
    return entries_[idx].file_line_col;
  }

  // Returns a full human-readable description for idx-th entry.
  std::string full_description(size_t idx) const {
    return func(idx) + " " + location(idx);
  }

  // Defines a symbol table entry.
  struct Entry {
    std::string func;
    std::string file_line_col;
    bool operator==(const Entry &other) const;
  };

  // Add function name and file location to symbol table.
  void AddEntry(std::string_view func, std::string_view file_line_col) {
    entries_.push_back({std::string(func), std::string(file_line_col)});
  }

 private:
  std::vector<Entry> entries_;
};

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_SYMBOL_TABLE_H_
