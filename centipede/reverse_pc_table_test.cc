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

#include "./centipede/reverse_pc_table.h"

#include "gtest/gtest.h"

namespace centipede {
namespace {

TEST(ReversePCTable, ReversePCTable) {
  static ReversePCTable table;
  table.SetFromPCs({500, 400, 100, 200, 300});

  EXPECT_EQ(table.NumPcs(), 5);
  EXPECT_EQ(table.GetPCIndex(0), ReversePCTable::kUnknownPC);
  EXPECT_EQ(table.GetPCIndex(50), ReversePCTable::kUnknownPC);
  EXPECT_EQ(table.GetPCIndex(150), ReversePCTable::kUnknownPC);
  EXPECT_EQ(table.GetPCIndex(501), ReversePCTable::kUnknownPC);

  EXPECT_EQ(table.GetPCIndex(500), 0);
  EXPECT_EQ(table.GetPCIndex(400), 1);
  EXPECT_EQ(table.GetPCIndex(100), 2);
  EXPECT_EQ(table.GetPCIndex(200), 3);
  EXPECT_EQ(table.GetPCIndex(300), 4);

  // Reset the table and try new values.
  table.SetFromPCs({40, 20, 30});
  EXPECT_EQ(table.GetPCIndex(200), ReversePCTable::kUnknownPC);
  EXPECT_EQ(table.GetPCIndex(40), 0);
  EXPECT_EQ(table.GetPCIndex(20), 1);
  EXPECT_EQ(table.GetPCIndex(30), 2);
}

}  // namespace
}  // namespace centipede
