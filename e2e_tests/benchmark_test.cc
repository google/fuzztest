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

#include <filesystem>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "absl/flags/parse.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "absl/time/time.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/subprocess.h"

// Mimic the open source google benchmark flags in order to work with benchmark
// driver tools.
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

// This parses the crash report output of a fuzz test.
// We might want to pass a richer format later.
Stats ParseStats(std::string_view output) {
  std::vector<std::string> lines = absl::StrSplit(output, '\n');
  const auto get_int = [](std::string_view line) -> uint64_t {
    std::vector<std::string> p = absl::StrSplit(line, ": ");
    if (p.size() != 2) return 0;
    uint64_t i;
    if (!absl::SimpleAtoi(p.back(), &i)) return 0;
    return i;
  };
  int i = 0;
  while (i < lines.size() && !absl::StartsWith(lines[i], "Elapsed seconds"))
    ++i;
  if (i + 4 >= lines.size()) return {};
  return {get_int(lines[i]), get_int(lines[i + 1]), get_int(lines[i + 2]),
          get_int(lines[i + 3]), get_int(lines[i + 4])};
}

std::string SingleJsonResult(std::string_view name, uint64_t value) {
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
  const std::vector<std::string> fuzz_test_names =
      absl::StrSplit(std_out, '\n', absl::SkipWhitespace());

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
