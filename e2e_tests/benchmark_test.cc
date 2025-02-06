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

// Benchmark test.
//
// It runs each micro-benchmark fuzz test in a child process and measures the
// time and number of iterations it takes to find the exit condition.

#include <sys/types.h>
#include <unistd.h>

#include <cstddef>
#include <cstdint>
#include <filesystem>  // NOLINT
#include <iostream>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "absl/time/time.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/subprocess.h"
#include "re2/re2.h"

// Mimic the open source google benchmark flags in order to work with
// benchmark driver tools.
ABSL_FLAG(std::string, benchmark_filter, "", "");
ABSL_FLAG(bool, benchmark_list_tests, false, "");
ABSL_FLAG(std::string, benchmark_format, "", "");

namespace {

struct Stats {
  uint64_t nanos;
  uint64_t runs;
  uint64_t edges_covered;
  uint64_t total_edges;
  uint64_t corpus_size;
};

struct TestResult {
  std::string test_name;
  Stats stats;
};

std::string SelfPath() {
  char buf[4096];
  ssize_t len = readlink("/proc/self/exe", buf, sizeof(buf));
  FUZZTEST_INTERNAL_CHECK(len < sizeof(buf), "Path too long!");
  return std::string(buf, len);
}
std::string MicrobenchmarksBinaryPath() {
  const std::string self_path = SelfPath();
  const std::size_t dir_path_len = self_path.find_last_of('/');
  std::string binary_path = self_path.substr(0, dir_path_len) +
                            "/testdata/fuzz_tests_for_microbenchmarking";
  FUZZTEST_INTERNAL_CHECK(std::filesystem::exists(binary_path), "Can't find ",
                          binary_path);
  return binary_path;
}

uint64_t ExtractTime(absl::string_view output) {
  static constexpr LazyRE2 kElapsedTimeRE = {"\nElapsed time: (.+)\n"};
  std::string duration_str;
  FUZZTEST_INTERNAL_CHECK(
      RE2::PartialMatch(output, *kElapsedTimeRE, &duration_str),
      "\n\nCould not find:\n\nElapsed time:\n\nin:\n\n", output);
  absl::Duration duration;
  FUZZTEST_INTERNAL_CHECK(absl::ParseDuration(duration_str, &duration),
                          "Could not parse duration:", duration_str);
  return absl::ToInt64Nanoseconds(duration);
}

uint64_t ExtractNumber(absl::string_view output, absl::string_view name) {
  uint64_t number;
  FUZZTEST_INTERNAL_CHECK(
      RE2::PartialMatch(output, absl::StrCat("\n", name, ": (.+)\n"), &number),
      "\n\nCould not find\n\n", name, ":\n\nin:\n\n", output);
  return number;
}

// This parses the crash report output of a fuzz test, which looks something
// like this:
//
// Elapsed time: 294.414351ms
// Total runs: 10000
// Edges covered: 35
// Total edges: 263165
// Corpus size: 264
// Max stack used: 32
//
// We might want to pass a richer format later.
Stats ParseStats(absl::string_view output) {
  return {
      /*nanos=*/ExtractTime(output),
      /*runs=*/ExtractNumber(output, "Total runs"),
      /*edges_covered=*/ExtractNumber(output, "Edges covered"),
      /*total_edges=*/ExtractNumber(output, "Total edges"),
      /*corpus_size=*/ExtractNumber(output, "Corpus size"),
  };
}

std::string SingleJsonResult(absl::string_view name, uint64_t value) {
  constexpr absl::string_view kJsonFormat = R"(    {
      "cpu_time": %u,
      "real_time": %u,
      "iterations": 1,
      "name": "%s",
      "time_unit": "ns"
    })";
  return absl::StrFormat(kJsonFormat, value, value, name);
}

std::string AllJsonResults(const std::vector<TestResult>& test_results) {
  std::vector<std::string> json_results;

  for (const TestResult& result : test_results) {
    if (result.test_name == "Control.Iters10000") {
      json_results.push_back(SingleJsonResult(
          absl::StrCat(result.test_name, "(time)"), result.stats.nanos));
      // We also generate a synthetic control result for 10000 total edges.
      // This measures the cost of the framework on processing the edge map.
      // This way we can see if differences in a CL come from edge count
      // change or from implementation changes.
      FUZZTEST_INTERNAL_CHECK(result.stats.total_edges != 0,
                              "Total edges cannot be zero!");
      json_results.push_back(SingleJsonResult(
          "Control.Edges10000(time)",
          10000 * result.stats.nanos / result.stats.total_edges));
    } else {
      json_results.push_back(SingleJsonResult(
          absl::StrCat(result.test_name, "(runs)"), result.stats.runs));
      json_results.push_back(SingleJsonResult(
          absl::StrCat(result.test_name, "(time)"), result.stats.nanos));
    }
  }

  constexpr absl::string_view kJsonTemplate = R"(
{
  "benchmarks": [
%s
  ],
  "context": {}
})";
  return absl::StrFormat(kJsonTemplate, absl::StrJoin(json_results, ",\n"));
}

Stats RunFuzzTest(const std::string& name) {
  std::cerr << "[.] Running: " << name << '\n';
  constexpr int kTimeOutSecs = 30;
  std::vector<std::string> command_line = {MicrobenchmarksBinaryPath(),
                                           "--fuzz", name};
  auto [status, std_out, std_err] = fuzztest::internal::RunCommand(
      command_line,
      /*environment=*/{}, absl::Seconds(kTimeOutSecs));
  // Overread tests under asan might not produce any stat.
  if (absl::StrContains(name, "Overread")) return {};
  return ParseStats(std_err);
}

bool TestNameMatchesFilter(absl::string_view test_name,
                           absl::string_view filter) {
  return test_name == filter ||
         (test_name == "Control.Iters10000" && filter == "Control.Edges10000");
}

void RunMicrobenchmarks(const bool list_tests, const std::string& filter) {
  std::vector<TestResult> test_results;

  // Get the list of fuzz tests in the `microbenchmarks` binary.
  auto [status, std_out, std_err] = fuzztest::internal::RunCommand(
      {MicrobenchmarksBinaryPath(), "--list_fuzz_tests"});
  const std::vector<std::string> std_out_lines =
      absl::StrSplit(std_out, '\n', absl::SkipWhitespace());
  std::vector<std::string> fuzz_test_names;
  fuzz_test_names.reserve(std_out_lines.size());
  for (absl::string_view line : std_out_lines) {
    static constexpr absl::string_view kFuzzTestPrefix = "[*] Fuzz test: ";
    if (absl::ConsumePrefix(&line, kFuzzTestPrefix)) {
      fuzz_test_names.push_back(std::string(line));
    }
  }

  if (list_tests) {
    for (const std::string& name : fuzz_test_names) {
      std::cout << name << '\n';
    }
    // Synthetic control test
    std::cout << "Control.Edges10000" << '\n';
    return;
  }

  const bool has_filter = !filter.empty() && filter != "all" && filter != ".*";
  for (const std::string& name : fuzz_test_names) {
    // NOTE: This should support regex, but let's keep it simple for now.
    if (has_filter && !TestNameMatchesFilter(name, filter)) continue;

    Stats stats = RunFuzzTest(name);
    test_results.push_back({name, stats});
  }

  std::cout << AllJsonResults(test_results);
}

}  // namespace

int main(int argc, char** argv) {
#if defined(__has_feature)
#if !__has_feature(coverage_sanitizer)
  FUZZTEST_INTERNAL_CHECK(false,
                          "\n\nPlease compile with --config=fuzztest.\n");
#endif
#endif
  absl::ParseCommandLine(argc, argv);
  const bool list_tests = absl::GetFlag(FLAGS_benchmark_list_tests);
  const std::string filter = absl::GetFlag(FLAGS_benchmark_filter);
  RunMicrobenchmarks(list_tests, filter);
}
