// Copyright 2026 The FuzzTest Authors.
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

#include <filesystem>  // NOLINT
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>  // NOLINT
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/time/time.h"
#include "./centipede/command.h"
#include "./common/logging.h"
#include "./common/test_util.h"

ABSL_FLAG(int, seed, 0, "The random seed to use");
ABSL_FLAG(std::string, puzzle, "", "The name of the puzzle to run");

namespace fuzztest::internal {
namespace {

using testing::ContainsRegex;
using testing::Value;

std::string ReadFile(std::filesystem::path path) {
  std::ifstream file(path);
  std::stringstream ss;
  ss << file.rdbuf();
  return ss.str();
}

constexpr std::string_view kCasePrefix = "// CASE ";
constexpr std::string_view kArgPrefix = "ARG:";
constexpr std::string_view kMatchPrefix = "MATCH:";

std::vector<std::string> GetCasesInPuzzle(std::string_view puzzle) {
  const std::string puzzle_source_path =
      GetDataDependencyFilepath(
          absl::StrCat("centipede/puzzles/", puzzle, ".cc"))
          .string();
  std::error_code ec;
  FUZZTEST_CHECK(std::filesystem::exists(puzzle_source_path, ec))
      << "Puzzle source " << puzzle_source_path << " does not exist";
  const std::string puzzle_source = ReadFile(puzzle_source_path);
  std::set<std::string> found_cases;
  for (std::string_view line : absl::StrSplit(puzzle_source, '\n')) {
    const auto case_start_pos = line.find(kCasePrefix);
    if (case_start_pos == line.npos) continue;
    const auto case_end_pos =
        line.find(":", case_start_pos + kCasePrefix.size());
    if (case_end_pos == line.npos) continue;
    if (line.find(kMatchPrefix, case_end_pos) == line.npos) continue;
    found_cases.insert(std::string{
        line.substr(case_start_pos + kCasePrefix.size(),
                    case_end_pos - case_start_pos - kCasePrefix.size())});
  }
  return {found_cases.begin(), found_cases.end()};
}

class PuzzleTest : public testing::Test {
 public:
  PuzzleTest(std::string_view puzzle, std::string_view case_name)
      : puzzle_{puzzle}, case_name_{case_name} {}

  void TestBody() {
    const std::string centipede_path =
        GetDataDependencyFilepath("centipede/centipede_uninstrumented")
            .string();
    const std::string puzzle_binary_path =
        GetDataDependencyFilepath(absl::StrCat("centipede/puzzles/", puzzle_))
            .string();
    const std::string puzzle_source_path =
        GetDataDependencyFilepath(
            absl::StrCat("centipede/puzzles/", puzzle_, ".cc"))
            .string();
    std::error_code ec;
    FUZZTEST_CHECK(std::filesystem::exists(puzzle_binary_path, ec))
        << "Puzzle binary " << puzzle_binary_path << " does not exist";
    FUZZTEST_CHECK(std::filesystem::exists(puzzle_source_path, ec))
        << "Puzzle source " << puzzle_source_path << " does not exist";
    TempDir tmp_dir{absl::StrCat(puzzle_, "_", case_name_)};

    const std::string case_prefix = absl::StrCat(kCasePrefix, case_name_, ":");
    std::vector<std::string> extra_args;
    std::vector<std::string> output_matches;
    const std::string puzzle_source = ReadFile(puzzle_source_path);
    for (std::string_view line : absl::StrSplit(puzzle_source, '\n')) {
      const auto case_pos = line.find(case_prefix);
      if (case_pos == line.npos) continue;
      if (const auto arg_pos =
              line.find(kArgPrefix, case_pos + case_prefix.size());
          arg_pos != line.npos) {
        auto arg = std::string{absl::StripAsciiWhitespace(
            line.substr(arg_pos + kArgPrefix.size()))};
        FUZZTEST_LOG(INFO) << "Using arg: " << arg;
        extra_args.push_back(std::move(arg));
        continue;
      }
      if (const auto output_match_pos =
              line.find(kMatchPrefix, case_pos + case_prefix.size());
          output_match_pos != line.npos) {
        auto output_match = std::string{absl::StripAsciiWhitespace(
            line.substr(output_match_pos + kMatchPrefix.size()))};
        FUZZTEST_LOG(INFO) << "Using match: " << output_match;
        output_matches.push_back(std::move(output_match));
        continue;
      }
    }
    FUZZTEST_CHECK(!output_matches.empty())
        << "Need at least one output match for case " << case_name_;

    Command::Options cmd_options;
    cmd_options.args = {
        absl::StrCat("--workdir=", (tmp_dir.path() / "workdir").string()),
        absl::StrCat("--binary=", puzzle_binary_path),
        "--populate_binary_info=0",
        absl::StrCat("--seed=", absl::GetFlag(FLAGS_seed)),
        "--num_runs=2000000",
        "--shmem_size_mb=100",
        "--exit_on_crash",
    };
    cmd_options.args.insert(cmd_options.args.end(), extra_args.begin(),
                            extra_args.end());

    const std::string output_prefix = (tmp_dir.path() / "out_").string();
    cmd_options.stdout_file_prefix = output_prefix;
    cmd_options.stderr_file_prefix = output_prefix;
    Command cmd(centipede_path, cmd_options);
    FUZZTEST_CHECK(cmd.ExecuteAsync());
    (void)cmd.Wait(absl::Now() + absl::Seconds(30));
    const std::string output = ReadFile(cmd.stdout_file());
    for (const auto& output_match : output_matches) {
      EXPECT_TRUE(Value(output, ContainsRegex(output_match))) << output;
    }
  }

 private:
  std::string puzzle_;
  std::string case_name_;
};

}  // namespace
}  // namespace fuzztest::internal

int main(int argc, char** argv) {
  absl::ParseCommandLine(argc, argv);
  testing::InitGoogleTest(&argc, argv);
  const std::string puzzle = absl::GetFlag(FLAGS_puzzle);
  FUZZTEST_CHECK(!puzzle.empty());
  const auto cases = fuzztest::internal::GetCasesInPuzzle(puzzle);
  for (const auto& case_name : cases) {
    testing::RegisterTest(
        "Puzzle", case_name.c_str(), nullptr, nullptr, __FILE__, __LINE__,
        [puzzle, case_name]() -> testing::Test* {
          return new fuzztest::internal::PuzzleTest{puzzle, case_name};
        });
  }
  return RUN_ALL_TESTS();
}
