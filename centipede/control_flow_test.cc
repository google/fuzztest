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

#include "./centipede/control_flow.h"

#include <cstddef>
#include <cstdint>
#include <thread>  //NOLINT
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./centipede/binary_info.h"
#include "./centipede/defs.h"
#include "./centipede/logging.h"
#include "./centipede/symbol_table.h"
#include "./centipede/test_util.h"

namespace centipede {

// Mock CFTable representing the following cfg:
//    1
//  /   \
// 2     3
//  \   /
//    4
// TODO(ussuri): Change PCs to 100, 200 etc, to avoid confusion with PCIndex.
static const CFTable g_cf_table = {1, 2, 3, 0, 0, 2, 4, 0,
                                   0, 3, 4, 0, 0, 4, 0, 0};
static const PCTable g_pc_table = {
    {1, PCInfo::kFuncEntry}, {2, 0}, {3, 0}, {4, 0}};

TEST(ControlFlowGraph, ComputeReachabilityForPc) {
  ControlFlowGraph cfg;
  cfg.InitializeControlFlowGraph(g_cf_table, g_pc_table);
  EXPECT_NE(cfg.size(), 0);

  auto reach1 = cfg.ComputeReachabilityForPc(1);
  auto reach2 = cfg.ComputeReachabilityForPc(2);
  auto reach3 = cfg.ComputeReachabilityForPc(3);
  auto reach4 = cfg.ComputeReachabilityForPc(4);

  EXPECT_THAT(reach1, testing::UnorderedElementsAre(1, 2, 3, 4));
  EXPECT_THAT(reach2, testing::UnorderedElementsAre(2, 4));
  EXPECT_THAT(reach3, testing::UnorderedElementsAre(3, 4));
  EXPECT_THAT(reach4, testing::ElementsAre(4));
}

namespace {

TEST(CFTable, MakeCfgFromCfTable) {
  ControlFlowGraph cfg;
  cfg.InitializeControlFlowGraph(g_cf_table, g_pc_table);
  EXPECT_NE(cfg.size(), 0);

  for (auto &pc : {1, 2, 3, 4}) {
    SCOPED_TRACE(testing::Message() << VV(pc));
    EXPECT_TRUE(cfg.exists(pc));

    // Check that cfg traversal is possible.
    auto successors = cfg.GetSuccessors(pc);
    for (auto &successor : successors) {
      EXPECT_TRUE(cfg.exists(successor));
    }

    EXPECT_THAT(cfg.GetSuccessors(1).size(), 2);
    EXPECT_THAT(cfg.GetSuccessors(2).size(), 1);
    EXPECT_THAT(cfg.GetSuccessors(3).size(), 1);
    EXPECT_TRUE(cfg.GetSuccessors(4).empty());
  }

  CHECK_EQ(cfg.GetPcIndex(1), 0);
  CHECK_EQ(cfg.GetPcIndex(2), 1);
  CHECK_EQ(cfg.GetPcIndex(3), 2);
  CHECK_EQ(cfg.GetPcIndex(4), 3);

  EXPECT_TRUE(cfg.BlockIsFunctionEntry(0));
  EXPECT_FALSE(cfg.BlockIsFunctionEntry(1));
  EXPECT_FALSE(cfg.BlockIsFunctionEntry(2));
  EXPECT_FALSE(cfg.BlockIsFunctionEntry(3));

  CHECK_EQ(cfg.GetCyclomaticComplexity(1), 2);
}

TEST(FunctionComplexity, ComputeFuncComplexity) {
  static const CFTable g_cf_table1 = {
      1, 2, 3, 0, 0,  // 1 goes to 2 and 3.
      2, 3, 4, 0, 0,  // 2 goes to 3 and 4.
      3, 1, 4, 0, 0,  // 3 goes to 1 and 4.
      4, 0, 0         // 4 goes nowhere.
  };
  static const CFTable g_cf_table2 = {
      1, 0, 0,  // 1 goes nowhere.
  };
  static const CFTable g_cf_table3 = {
      1, 2, 0, 0,  // 1 goes to 2.
      2, 3, 0, 0,  // 2 goes to 3.
      3, 1, 0, 0,  // 3 goes to 1.
  };
  static const CFTable g_cf_table4 = {
      1, 2, 3, 0, 0,  // 1 goes to 2 and 3.
      2, 3, 4, 0, 0,  // 2 goes to 3 and 4.
      3, 0, 0,        // 3 goes nowhere.
      4, 0, 0         // 4 goes nowhere.
  };

  ControlFlowGraph cfg1;
  cfg1.InitializeControlFlowGraph(g_cf_table1, g_pc_table);
  EXPECT_NE(cfg1.size(), 0);

  ControlFlowGraph cfg2;
  cfg2.InitializeControlFlowGraph(g_cf_table2, g_pc_table);
  EXPECT_NE(cfg2.size(), 0);

  ControlFlowGraph cfg3;
  cfg3.InitializeControlFlowGraph(g_cf_table3, g_pc_table);
  EXPECT_NE(cfg3.size(), 0);

  ControlFlowGraph cfg4;
  cfg4.InitializeControlFlowGraph(g_cf_table4, g_pc_table);
  EXPECT_NE(cfg4.size(), 0);

  EXPECT_EQ(ComputeFunctionCyclomaticComplexity(1, cfg1), 4);
  EXPECT_EQ(ComputeFunctionCyclomaticComplexity(1, cfg2), 1);
  EXPECT_EQ(ComputeFunctionCyclomaticComplexity(1, cfg3), 2);
  EXPECT_EQ(ComputeFunctionCyclomaticComplexity(1, cfg4), 2);
}

TEST(ControlFlowGraph, LazyReachability) {
  ControlFlowGraph cfg;
  cfg.InitializeControlFlowGraph(g_cf_table, g_pc_table);
  EXPECT_NE(cfg.size(), 0);

  auto rt = [&]() {
    for (int i = 0; i < 10; ++i) {
      cfg.LazyGetReachabilityForPc(1);
      cfg.LazyGetReachabilityForPc(2);
      cfg.LazyGetReachabilityForPc(3);
      cfg.LazyGetReachabilityForPc(4);
    }
    auto reach1 = cfg.LazyGetReachabilityForPc(1);
    auto reach2 = cfg.LazyGetReachabilityForPc(2);
    auto reach3 = cfg.LazyGetReachabilityForPc(3);
    auto reach4 = cfg.LazyGetReachabilityForPc(4);

    EXPECT_THAT(reach1, testing::UnorderedElementsAre(1, 2, 3, 4));
    EXPECT_THAT(reach2, testing::UnorderedElementsAre(2, 4));
    EXPECT_THAT(reach3, testing::UnorderedElementsAre(3, 4));
    EXPECT_THAT(reach4, testing::ElementsAre(4));
  };

  std::thread t1(rt), t2(rt), t3(rt);
  t1.join();
  t2.join();
  t3.join();
}

// Returns a path for i-th temporary file.
static std::string GetTempFilePath(size_t i) {
  return std::filesystem::path(GetTestTempDir())
      .append(absl::StrCat("coverage_test", i, "-", getpid()));
}

// Returns path to test_fuzz_target.
static std::string GetTargetPath() {
  return GetDataDependencyFilepath("centipede/testing/test_fuzz_target");
}

// Returns path to llvm-symbolizer.
static std::string GetLLVMSymbolizerPath() {
  CHECK_EQ(system("which llvm-symbolizer"), EXIT_SUCCESS)
      << "llvm-symbolizer has to be installed and findable via PATH";
  return "llvm-symbolizer";
}

// Returns path to objdump.
static std::string GetObjDumpPath() {
  CHECK_EQ(system("which objdump"), EXIT_SUCCESS)
      << "objdump has to be installed and findable via PATH";
  return "objdump";
}

// Tests GetCfTableFromBinary() on test_fuzz_target.
TEST(CFTable, GetCfTable) {
  auto target_path = GetTargetPath();
  std::string tmp_path1 = GetTempFilePath(1);
  std::string tmp_path2 = GetTempFilePath(2);

  // Load the cf table.
  BinaryInfo binary_info;
  binary_info.InitializeFromSanCovBinary(
      target_path, GetObjDumpPath(), GetLLVMSymbolizerPath(), GetTestTempDir());
  const auto &cf_table = binary_info.cf_table;
  LOG(INFO) << VV(target_path) << VV(tmp_path1) << VV(cf_table.size());
  if (cf_table.empty()) {
    LOG(INFO) << "__sancov_cfs is empty.";
    // TODO(ussuri): This should be removed once OSS clang supports
    //  control-flow.
    GTEST_SKIP();
  }

  ASSERT_FALSE(
      std::filesystem::exists(tmp_path1.c_str()));  // tmp_path1 was deleted.
  LOG(INFO) << VV(cf_table.size());

  const auto &pc_table = binary_info.pc_table;
  EXPECT_FALSE(binary_info.uses_legacy_trace_pc_instrumentation);
  EXPECT_THAT(pc_table.empty(), false);

  const SymbolTable &symbols = binary_info.symbols;

  absl::flat_hash_map<uintptr_t, size_t> pc_table_index;
  for (size_t i = 0; i < pc_table.size(); i++) {
    pc_table_index[pc_table[i].pc] = i;
  }

  for (size_t j = 0; j < cf_table.size();) {
    auto current_pc = cf_table[j];
    ++j;
    size_t successor_num = 0;
    size_t callee_num = 0;
    size_t icallee_num = 0;

    // Iterate over successors.
    while (cf_table[j]) {
      ++successor_num;
      ++j;
    }
    ++j;  // Step over the delimiter.

    // Iterate over callees.
    while (cf_table[j]) {
      if (cf_table[j] > 0) ++callee_num;
      if (cf_table[j] < 0) ++icallee_num;
      ++j;
    }
    ++j;  // Step over the delimiter.

    // Determine if current_pc is a function entry.
    if (pc_table_index.contains(current_pc)) {
      size_t index = pc_table_index[current_pc];
      if (pc_table[index].has_flag(PCInfo::kFuncEntry)) {
        const std::string &current_function = symbols.func(index);
        // Check for properties.
        SCOPED_TRACE(testing::Message()
                     << "Checking for " << VV(current_function)
                     << VV(current_pc));
        if (current_function == "SingleEdgeFunc") {
          EXPECT_EQ(successor_num, 0);
          EXPECT_EQ(icallee_num, 0);
          EXPECT_EQ(callee_num, 0);
        } else if (current_function == "MultiEdgeFunc") {
          EXPECT_EQ(successor_num, 2);
          EXPECT_EQ(icallee_num, 0);
          EXPECT_EQ(callee_num, 0);
        } else if (current_function == "IndirectCallFunc") {
          EXPECT_EQ(successor_num, 0);
          EXPECT_EQ(icallee_num, 1);
          EXPECT_EQ(callee_num, 0);
        }
      }
    }
  }
}

}  // namespace

}  // namespace centipede
