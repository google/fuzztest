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

#include <sstream>
#include <string>

#include "gtest/gtest.h"
#include "./centipede/pc_info.h"
#include "./centipede/symbol_table.h"
#include "./centipede/test_util.h"

namespace centipede {
namespace {

TEST(BinaryInfoTest, SerializesAndDeserializesBinaryInfoSuccessfully) {
  PCTable input_pcs = {{.pc = 0, .flags = 1}, {.pc = 2, .flags = 3}};
  std::string input_symbols =
      R"(FunctionOne
    source/location/one.cc:1:0

    FunctionTwo
    source/location/two.cc:2:0

)";
  std::istringstream input_stream(input_symbols);
  SymbolTable symbol_table;
  symbol_table.ReadFromLLVMSymbolizer(input_stream);
  BinaryInfo input = {.pc_table = input_pcs, .symbols = symbol_table};

  auto temp_dir = GetTestTempDir(test_info_->name());
  input.Write(temp_dir);
  BinaryInfo output;
  output.Read(temp_dir);

  EXPECT_EQ(input.pc_table, output.pc_table);
  EXPECT_EQ(input.symbols, output.symbols);
}

}  // namespace
}  // namespace centipede
