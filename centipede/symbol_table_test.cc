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

#include "./centipede/symbol_table.h"

#include <string>
#include <string_view>

#include "gtest/gtest.h"
#include "riegeli/bytes/string_reader.h"
#include "riegeli/bytes/string_writer.h"

namespace centipede {
namespace {

TEST(SymbolTableTest, SerializesAndDeserializesCorrectly) {
  const std::string_view input =
      R"(FunctionOne
    source/location/one.cc:1:0

    FunctionTwo
    source/location/two.cc:2:0

)";
  SymbolTable symbol_table;
  symbol_table.ReadFromLLVMSymbolizer(riegeli::StringReader(input));

  std::string output;
  symbol_table.WriteToLLVMSymbolizer(riegeli::StringWriter(&output));
  EXPECT_EQ(input, output);
}

TEST(SymbolTableTest, SerializesAndDeserializesCorrectlyWithUnknownFile) {
  const std::string_view input =
      R"(?
    ?

)";
  SymbolTable symbol_table;
  symbol_table.ReadFromLLVMSymbolizer(riegeli::StringReader(input));

  std::string output;
  symbol_table.WriteToLLVMSymbolizer(riegeli::StringWriter(&output));
  EXPECT_EQ(input, output);
}

}  // namespace
}  // namespace centipede
