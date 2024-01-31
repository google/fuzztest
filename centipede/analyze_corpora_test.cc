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

#include "./centipede/analyze_corpora.h"

#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "./centipede/binary_info.h"
#include "./centipede/environment.h"
#include "./centipede/symbol_table.h"
#include "./centipede/test_coverage_util.h"
#include "./centipede/test_util.h"

namespace centipede {
namespace {

// Returns path to test_fuzz_target.
static std::string GetTargetPath() {
  return GetDataDependencyFilepath("centipede/testing/test_fuzz_target");
}

// TODO(ussuri): Implement.
TEST(AnalyzeCorpora, AnalyzeCorpora) { LOG(INFO) << "Unimplemented"; }

TEST(GetCoverage, SimpleCoverageResults) {
  Environment env;
  env.binary = GetTargetPath();
  auto corpus_records = RunInputsAndCollectCorpusRecords(env, {"func1"});
  EXPECT_EQ(corpus_records.size(), 1);
  // Get pc_table and symbols.
  bool uses_legacy_trace_pc_instrumentation = {};
  BinaryInfo binary_info;
  binary_info.InitializeFromSanCovBinary(
      GetTargetPath(), GetObjDumpPath(), GetLLVMSymbolizerPath(),
      GetTestTempDir(test_info_->name()).string());
  const auto &pc_table = binary_info.pc_table;
  EXPECT_FALSE(uses_legacy_trace_pc_instrumentation);
  const SymbolTable &symbols = binary_info.symbols;
  // pc_table and symbols should have the same size.
  EXPECT_EQ(pc_table.size(), symbols.size());
  CoverageResults res = GetCoverage(corpus_records, std::move(binary_info));
  // Check that inputs cover LLVMFuzzerTestOneInput and SingleEdgeFunc, but not
  // MultiEdgeFunc.
  size_t llvm_fuzzer_test_one_input_num_edges = 0;
  size_t single_edge_func_num_edges = 0;
  size_t multi_edge_func_num_edges = 0;
  for (size_t pc : res.pcs) {
    size_t check_pc = pc;
    EXPECT_EQ(check_pc, pc);
    single_edge_func_num_edges +=
        res.binary_info.symbols.func(pc) == "SingleEdgeFunc";
    multi_edge_func_num_edges +=
        res.binary_info.symbols.func(pc) == "MultiEdgeFunc";
    llvm_fuzzer_test_one_input_num_edges +=
        res.binary_info.symbols.func(pc) == "LLVMFuzzerTestOneInput";
  }
  EXPECT_GT(llvm_fuzzer_test_one_input_num_edges, 1);
  EXPECT_EQ(single_edge_func_num_edges, 1);
  EXPECT_EQ(multi_edge_func_num_edges, 0);
}

}  // namespace
}  // namespace centipede
