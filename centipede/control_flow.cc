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

#include <filesystem>  // NOLINT
#include <fstream>
#include <queue>
#include <string>
#include <vector>

#include "absl/strings/match.h"
#include "./centipede/command.h"
#include "./centipede/defs.h"
#include "./centipede/logging.h"
#include "./centipede/util.h"

namespace centipede {

PCTable GetPcTableFromBinary(std::string_view binary_path,
                             std::string_view objdump_path,
                             std::string_view tmp_path,
                             bool *uses_legacy_trace_pc_instrumentation) {
  PCTable res = GetPcTableFromBinaryWithPcTable(binary_path, tmp_path);
  if (res.empty()) {
    // Fall back to trace-pc.
    LOG(INFO) << "Fall back to GetPcTableFromBinaryWithTracePC";
    res = GetPcTableFromBinaryWithTracePC(binary_path, objdump_path, tmp_path);
    *uses_legacy_trace_pc_instrumentation = true;
  } else {
    *uses_legacy_trace_pc_instrumentation = false;
  }
  return res;
}

PCTable GetPcTableFromBinaryWithPcTable(std::string_view binary_path,
                                        std::string_view tmp_path) {
  Command cmd(binary_path, {},
              {absl::StrCat("CENTIPEDE_RUNNER_FLAGS=:dump_pc_table:arg1=",
                            tmp_path, ":")},
              "/dev/null");
  int exit_code = cmd.Execute();
  if (exit_code) {
    LOG(INFO) << __func__
              << ": Failed to get PC table from binary: " << VV(binary_path)
              << VV(cmd.ToString()) << VV(exit_code) << "; see logs above";
    return {};
  }
  ByteArray pc_infos_as_bytes;
  ReadFromLocalFile(tmp_path, pc_infos_as_bytes);
  std::filesystem::remove(tmp_path);
  CHECK_EQ(pc_infos_as_bytes.size() % sizeof(PCInfo), 0);
  size_t pc_table_size = pc_infos_as_bytes.size() / sizeof(PCInfo);
  const auto *pc_infos = reinterpret_cast<PCInfo *>(pc_infos_as_bytes.data());
  PCTable pc_table{pc_infos, pc_infos + pc_table_size};
  CHECK_EQ(pc_table.size(), pc_table_size);
  return pc_table;
}

PCTable GetPcTableFromBinaryWithTracePC(std::string_view binary_path,
                                        std::string_view objdump_path,
                                        std::string_view tmp_path) {
  // Run objdump -d on the binary. Assumes objdump in PATH.
  Command cmd(objdump_path, {"-d", std::string(binary_path)}, {}, tmp_path,
              "/dev/null");
  int exit_code = cmd.Execute();
  if (exit_code) {
    LOG(INFO) << __func__
              << ": Failed to get PC table for binary: " << VV(binary_path)
              << VV(cmd.ToString()) << VV(exit_code) << "; see logs above";
    return {};
  }
  PCTable pc_table;
  std::ifstream in(std::string{tmp_path});
  CHECK(in.good()) << VV(tmp_path);
  bool saw_new_function = false;

  // Read the objdump output, find lines that start a function
  // and lines that have a call to __sanitizer_cov_trace_pc.
  // Reconstruct the PCTable from those.
  for (std::string line; std::getline(in, line);) {
    if (absl::EndsWith(line, ">:")) {  // new function.
      saw_new_function = true;
      continue;
    }
    if (!absl::EndsWith(line, "<__sanitizer_cov_trace_pc>") &&
        !absl::EndsWith(line, "<__sanitizer_cov_trace_pc@plt>"))
      continue;
    uintptr_t pc = std::stoul(line, nullptr, 16);
    uintptr_t flags = saw_new_function ? PCInfo::kFuncEntry : 0;
    saw_new_function = false;  // next trace_pc will be in the same function.
    pc_table.push_back({pc, flags});
  }
  std::filesystem::remove(tmp_path);
  return pc_table;
}

CFTable GetCfTableFromBinary(std::string_view binary_path,
                             std::string_view tmp_path) {
  Command cmd(binary_path, {},
              {absl::StrCat("CENTIPEDE_RUNNER_FLAGS=:dump_cf_table:arg1=",
                            tmp_path, ":")},
              "/dev/null", "/dev/null");
  int cmd_exit_code = cmd.Execute();
  if (cmd_exit_code != EXIT_SUCCESS) {
    LOG(ERROR) << "CF table dumping failed: " << VV(cmd.ToString())
               << VV(cmd_exit_code);
    return {};
  }
  ByteArray cf_infos_as_bytes;
  ReadFromLocalFile(tmp_path, cf_infos_as_bytes);
  std::filesystem::remove(tmp_path);

  size_t cf_table_size = cf_infos_as_bytes.size() / sizeof(CFTable::value_type);
  const auto *cf_infos =
      reinterpret_cast<CFTable::value_type *>(cf_infos_as_bytes.data());
  CFTable cf_table{cf_infos, cf_infos + cf_table_size};
  CHECK_EQ(cf_table.size(), cf_table_size);
  return cf_table;
}

void ControlFlowGraph::InitializeControlFlowGraph(const CFTable &cf_table,
                                                  const PCTable &pc_table) {
  CHECK(!cf_table.empty());
  func_entries_.resize(pc_table.size());
  reachability_.resize(pc_table.size());

  for (size_t j = 0; j < cf_table.size();) {
    std::vector<uintptr_t> successors;
    auto curr_pc = cf_table[j];
    ++j;

    // Iterate over successors.
    while (cf_table[j]) {
      successors.push_back(cf_table[j]);
      ++j;
    }
    ++j;  // Step over the delimiter.

    // Record the list of successors
    graph_[curr_pc] = std::move(successors);
    // TODO(ussuri): Remove after debugging.
    VLOG(100) << "Added PC: " << curr_pc;

    // Iterate over callees.
    while (cf_table[j]) {
      ++j;
    }
    ++j;  // Step over the delimiter.
    CHECK_LE(j, cf_table.size());
  }
  // Calculate cyclomatic complexity for all functions.
  for (PCIndex i = 0; i < pc_table.size(); ++i) {
    pc_index_map_[pc_table[i].pc] = i;
    if (pc_table[i].has_flag(PCInfo::kFuncEntry)) {
      func_entries_[i] = true;
      uintptr_t func_pc = pc_table[i].pc;
      auto func_comp = ComputeFunctionCyclomaticComplexity(func_pc, *this);
      function_complexities_[func_pc] = func_comp;
    }
  }
}

const std::vector<uintptr_t> &ControlFlowGraph::GetSuccessors(
    uintptr_t basic_block) const {
  auto it = graph_.find(basic_block);
  CHECK(it != graph_.end()) << VV(basic_block);
  return it->second;
}

std::vector<uintptr_t> ControlFlowGraph::ComputeReachabilityForPc(
    uintptr_t pc) const {
  absl::flat_hash_set<uintptr_t> visited_pcs;
  std::queue<uintptr_t> worklist;

  worklist.push(pc);
  while (!worklist.empty()) {
    auto current_pc = worklist.front();
    worklist.pop();
    if (!visited_pcs.insert(current_pc).second) continue;
    for (const auto &successor : graph_.at(current_pc)) {
      if (!exists(successor)) continue;
      worklist.push(successor);
    }
  }
  return {visited_pcs.begin(), visited_pcs.end()};
}

uint32_t ComputeFunctionCyclomaticComplexity(uintptr_t pc,
                                             const ControlFlowGraph &cfg) {
  size_t edge_num = 0, node_num = 0;

  absl::flat_hash_set<uintptr_t> visited_pcs;
  std::queue<uintptr_t> worklist;

  worklist.push(pc);

  while (!worklist.empty()) {
    auto current_pc = worklist.front();
    worklist.pop();
    if (!visited_pcs.insert(current_pc).second) continue;
    ++node_num;
    for (auto &successor : cfg.GetSuccessors(current_pc)) {
      if (!cfg.exists(successor)) continue;
      ++edge_num;
      worklist.push(successor);
    }
  }

  return edge_num - node_num + 2;
}

}  // namespace centipede
