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
#include <cstddef>
#include <fstream>
#include <ios>
#include <string>
#include <vector>

#include "absl/container/flat_hash_set.h"
#include "absl/log/check.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_split.h"
#include "./centipede/control_flow.h"
#include "./centipede/corpus.h"
#include "./centipede/coverage.pb.h"
#include "./centipede/feature.h"
#include "./centipede/logging.h"

namespace centipede {

namespace {

CoverageReport ToCoverageReport(const std::vector<size_t> &pcs,
                                const SymbolTable &symbols) {
  CoverageReport result;
  for (const size_t pc : pcs) {
    CoverageReport::Edge *edge = result.add_covered_edges();
    edge->set_function_name(symbols.func(pc));

    std::string file_line_column = symbols.location(pc);
    std::vector<std::string> file_line_column_split =
        absl::StrSplit(file_line_column, ':');
    CHECK(file_line_column_split.size() == 3)
        << "Unexpected number of elements when splitting source location: "
        << file_line_column;

    edge->set_file_name(file_line_column_split[0]);

    int line;
    CHECK(absl::SimpleAtoi(file_line_column_split[1], &line))
        << "Unable to convert line number to integer: "
        << file_line_column_split[1];
    edge->set_line(line);

    int column;
    CHECK(absl::SimpleAtoi(file_line_column_split[2], &column))
        << "Unable to convert column number to integer: "
        << file_line_column_split[2];
    edge->set_column(column);
  }
  return result;
}

}  // namespace

void AnalyzeCorpora(const BinaryInfo &binary_info,
                    const std::vector<CorpusRecord> &a,
                    const std::vector<CorpusRecord> &b,
                    std::string_view analyze_report_path) {
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
  absl::flat_hash_set<size_t> b_pcs;
  std::vector<size_t> b_shared_indices, b_unique_indices;
  for (size_t i = 0; i < b.size(); ++i) {
    const auto &record = b[i];
    bool has_b_only = false;
    for (const auto &feature : record.features) {
      if (!feature_domains::kPCs.Contains(feature)) continue;
      auto pc = ConvertPCFeatureToPcIndex(feature);
      b_pcs.insert(pc);
      if (a_pcs.contains(pc)) continue;
      b_only_pcs.insert(pc);
      has_b_only = true;
    }
    if (has_b_only)
      b_unique_indices.push_back(i);
    else
      b_shared_indices.push_back(i);
  }

  absl::flat_hash_set<size_t> a_only_pcs;
  for (const auto &record : a) {
    for (const auto &feature : record.features) {
      if (!feature_domains::kPCs.Contains(feature)) continue;
      auto pc = ConvertPCFeatureToPcIndex(feature);
      if (b_pcs.contains(pc)) continue;
      a_only_pcs.insert(pc);
    }
  }
  LOG(INFO) << VV(a.size()) << VV(b.size()) << VV(a_pcs.size())
            << VV(a_only_pcs.size()) << VV(b_only_pcs.size())
            << VV(b_shared_indices.size()) << VV(b_unique_indices.size());

  const auto &pc_table = binary_info.pc_table;
  const auto &symbols = binary_info.symbols;
  CoverageLogger coverage_logger(pc_table, symbols);

  // TODO: these cause a CHECK-fail
  // CoverageFrontier frontier_a(binary_info);
  // frontier_a.Compute(a);

  // TODO(kcc): use frontier_a to show the most interesting b-only PCs.

  // Sort PCs to print them in the canonical order, as in pc_table.
  std::vector<size_t> a_pcs_vec{a_pcs.begin(), a_pcs.end()};
  std::sort(a_pcs_vec.begin(), a_pcs_vec.end());
  std::vector<size_t> b_pcs_vec{b_pcs.begin(), b_pcs.end()};
  std::sort(b_pcs_vec.begin(), b_pcs_vec.end());
  std::vector<size_t> a_only_pcs_vec{a_only_pcs.begin(), a_only_pcs.end()};
  std::sort(a_only_pcs_vec.begin(), a_only_pcs_vec.end());
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

  if (!analyze_report_path.empty()) {
    AnalyzeReport analyze_report;
    CoverageReport *a_coverage = analyze_report.mutable_a_coverage();
    *a_coverage = ToCoverageReport(a_pcs_vec, symbols);
    CoverageReport *b_coverage = analyze_report.mutable_b_coverage();
    *b_coverage = ToCoverageReport(b_pcs_vec, symbols);
    CoverageReport *a_only_coverage = analyze_report.mutable_a_only_coverage();
    *a_only_coverage = ToCoverageReport(a_only_pcs_vec, symbols);
    CoverageReport *b_only_coverage = analyze_report.mutable_b_only_coverage();
    *b_only_coverage = ToCoverageReport(b_only_pcs_vec, symbols);

    std::fstream f(std::string{analyze_report_path},
                   std::ios::binary | std::ios::out);
    CHECK(f) << "Unable to open AnalyzeReport path: " << analyze_report_path;
    analyze_report.SerializeToOstream(&f);
    f.close();
  }
}

}  // namespace centipede
