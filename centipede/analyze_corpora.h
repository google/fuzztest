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

#ifndef THIRD_PARTY_CENTIPEDE_ANALYZE_CORPORA_H
#define THIRD_PARTY_CENTIPEDE_ANALYZE_CORPORA_H

#include <cstddef>
#include <string_view>
#include <vector>

#include "./centipede/binary_info.h"
#include "./centipede/corpus.h"

namespace centipede {

// The results of comparing corpus `a` with corpus `b`.
struct AnalyzeCorporaResults {
  std::vector<size_t> a_pcs;
  std::vector<size_t> b_pcs;
  std::vector<size_t> a_only_pcs;
  std::vector<size_t> b_only_pcs;
  BinaryInfo binary_info;
};

// Compares the corpus within `workdir_a` with the corpus in `workdir_b`.
AnalyzeCorporaResults AnalyzeCorpora(std::string_view binary_name,
                                     std::string_view binary_hash,
                                     std::string_view workdir_a,
                                     std::string_view workdir_b);

// Same as above but `LOG`s the results for human consumption.
void AnalyzeCorporaToLog(std::string_view binary_name,
                         std::string_view binary_hash,
                         std::string_view workdir_a,
                         std::string_view workdir_b);
}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_ANALYZE_CORPORA_H
