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

#include "./centipede/pc_info.h"

#include <ios>
#include <istream>
#include <ostream>

#include "absl/log/check.h"

namespace centipede {

PCTable ReadPcTable(std::istream &in) {
  in.seekg(0, std::ios_base::end);
  auto size = in.tellg();
  in.seekg(0, std::ios_base::beg);
  CHECK_EQ(size % sizeof(PCInfo), 0);
  PCTable pc_table(size / sizeof(PCInfo));
  in.read(reinterpret_cast<char *>(pc_table.data()), size);
  return pc_table;
}

void WritePcTable(const PCTable &pc_table, std::ostream &out) {
  out.write(reinterpret_cast<const char *>(pc_table.data()),
            pc_table.size() * sizeof(PCInfo));
}

}  // namespace centipede
