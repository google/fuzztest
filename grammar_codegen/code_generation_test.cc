// Copyright 2022 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "./grammar_codegen/code_generation.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"

namespace {

std::string GetContents(const std::string& path) {
  std::stringstream ss;
  ss << std::ifstream(path).rdbuf();
  return ss.str();
}

std::string RemoveWhiteSpace(absl::string_view s) {
  return absl::StrReplaceAll(s,
                             {{" ", ""}, {"\n", ""}, {"\r", ""}, {"\t", ""}});
}

std::string GetFuzzTestSrcDir() {
  const std::string src_dir = ::testing::SrcDir();
  return absl::StrCat(absl::StripSuffix(src_dir, "/"),
                      "/_main/");
}

// Removes lines that start with "//" from `s`.
std::string RemoveCommentLines(absl::string_view s) {
  std::vector<std::string> lines = absl::StrSplit(s, '\n');
  lines.erase(std::remove_if(lines.begin(), lines.end(),
                             [](absl::string_view line) {
                               return absl::StartsWith(line, "//");
                             }),
              lines.end());
  return absl::StrJoin(lines, "\n");
}

TEST(RemoveCommentLines, RemovesLinesStartingWithDoubleSlash) {
  EXPECT_EQ(RemoveCommentLines(R"(// comment 1
not a comment
// comment 2
not a comment again)"),
            R"(not a comment
not a comment again)");
}

TEST(CodeGeneration, GenerateValidJsonGrammarHeader) {
  const std::string src_dir = GetFuzzTestSrcDir();
  const std::vector<std::string> input_files{
      GetContents(absl::StrCat(src_dir, "fuzztest/grammars/JSON.g4"))};
  const std::string generated_header =
      fuzztest::internal::grammar::GenerateGrammarHeader(input_files, "json");
  const std::string ground_true_header = GetContents(absl::StrCat(
      src_dir, "grammar_codegen/testdata/expected_json_grammar.h"));

  // Check their contents are the same.
  EXPECT_EQ(RemoveWhiteSpace(RemoveCommentLines(generated_header)),
            RemoveWhiteSpace(RemoveCommentLines(ground_true_header)));
}

TEST(CodeGeneration, GenerateValidJsonGrammarHeaderWithSpaces) {
  const std::string src_dir = GetFuzzTestSrcDir();
  const std::vector<std::string> input_files{
      GetContents(absl::StrCat(src_dir, "fuzztest/grammars/JSON.g4"))};
  const std::string generated_header =
      fuzztest::internal::grammar::GenerateGrammarHeader(
          input_files, "json", /*insert_space_between_blocks=*/true);
  const std::string ground_true_header = GetContents(absl::StrCat(
      src_dir, "grammar_codegen/testdata/expected_json_grammar_with_spaces.h"));

  // Check their contents are the same.
  EXPECT_EQ(RemoveWhiteSpace(RemoveCommentLines(generated_header)),
            RemoveWhiteSpace(RemoveCommentLines(ground_true_header)));
}

}  // namespace
