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

#include <algorithm>

#include "absl/container/flat_hash_set.h"
#include "./centipede/control_flow.h"
#include "./centipede/corpus.h"
#include "./centipede/feature.h"
#include "./centipede/logging.h"

namespace centipede {
void AnalyzeCorpora(const BinaryInfo &binary_info,
                    const std::vector<CorpusRecord> &a,
                    const std::vector<CorpusRecord> &b) {
  // `a_pcs` will contain all PCs covered by `a`.
  absl::flat_hash_set<size_t> a_pcs;
  for (const auto &record : a) {
    for (const auto &feature : record.features) {
      if (!feature_domains::kPCs.Contains(feature)) continue;
      auto pc = ConvertPCFeatureToPcIndex(feature);
      a_pcs.insert(pc);
    }
  }

  // `b_only_pcs` will contain PCs covered by `b` but not by `a`.
  // `b_unique_indices` are indices of inputs that have PCs from `b_only_pcs`.
  // `b_shared_indices` are indices of all other inputs from `b`.
  absl::flat_hash_set<size_t> b_only_pcs;
  std::vector<size_t> b_shared_indices, b_unique_indices;
  for (size_t i = 0; i < b.size(); ++i) {
    const auto &record = b[i];
    bool has_b_only = false;
    for (const auto &feature : record.features) {
      if (!feature_domains::kPCs.Contains(feature)) continue;
      auto pc = ConvertPCFeatureToPcIndex(feature);
      if (a_pcs.contains(pc)) continue;
      b_only_pcs.insert(pc);
      has_b_only = true;
    }
    if (has_b_only)
      b_unique_indices.push_back(i);
    else
      b_shared_indices.push_back(i);
  }
  LOG(INFO) << VV(a.size()) << VV(b.size()) << VV(a_pcs.size())
            << VV(b_only_pcs.size()) << VV(b_shared_indices.size())
            << VV(b_unique_indices.size());

  const auto &pc_table = binary_info.pc_table;
  const auto &symbols = binary_info.symbols;
  CoverageLogger coverage_logger(pc_table, symbols);

  CoverageFrontier frontier_a(binary_info);
  frontier_a.Compute(a);

  // TODO(kcc): use frontier_a to show the most interesting b-only PCs.

  // Sort b-only PCs to print them in the canonical order, as in pc_table.
  std::vector<size_t> b_only_pcs_vec{b_only_pcs.begin(), b_only_pcs.end()};
  std::sort(b_only_pcs_vec.begin(), b_only_pcs_vec.end());

  // First, print the newly covered functions (including partially covered).
  LOG(INFO) << "B-only new functions:";
  absl::flat_hash_set<std::string_view> b_only_new_functions;
  for (const auto pc : b_only_pcs_vec) {
    if (!pc_table[pc].has_flag(PCInfo::kFuncEntry)) continue;
    auto str = coverage_logger.ObserveAndDescribeIfNew(pc);
    if (!str.empty()) LOG(INFO).NoPrefix() << str;
    b_only_new_functions.insert(symbols.func(pc));
  }

  // Now, print newly covered edges in functions that were covered in `a`.
  LOG(INFO) << "B-only new edges:";
  for (const auto pc : b_only_pcs_vec) {
    if (b_only_new_functions.contains(symbols.func(pc))) continue;
    auto str = coverage_logger.ObserveAndDescribeIfNew(pc);
    if (!str.empty()) LOG(INFO).NoPrefix() << str;
  }
}

}  // namespace centipede
