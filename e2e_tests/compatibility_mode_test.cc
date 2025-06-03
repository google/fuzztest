// Copyright 2025 Google LLC
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

#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "./common/temp_dir.h"
#include "./e2e_tests/test_binary_util.h"
#include "./fuzztest/internal/io.h"
#include "./fuzztest/internal/subprocess.h"

namespace fuzztest::internal {
namespace {

using testing::AllOf;
using testing::Eq;
using testing::HasSubstr;
using testing::IsEmpty;
using testing::Not;
using testing::SizeIs;

constexpr absl::string_view kDefaultTargetBinary =
    "testdata/fuzz_tests_for_functional_testing";

absl::flat_hash_map<std::string, std::string> WithTestSanitizerOptions(
    absl::flat_hash_map<std::string, std::string> env) {
  if (!env.contains("ASAN_OPTIONS")) {
    // Let both FuzzTest and sanitizer to handle abort to check
    // information from both sides. Use a random exitcode 111 for
    // sanitizer-caught crashes.
    env["ASAN_OPTIONS"] = "handle_abort=1:exitcode=111";
  }
  return env;
}

RunResults RunBinary(
    absl::flat_hash_map<std::string, std::string> fuzztest_flags,
    std::vector<std::string> binary_args = {},
    const absl::flat_hash_map<std::string, std::string>& env = {},
    absl::string_view target_binary = kDefaultTargetBinary) {
  RunOptions run_options;
  run_options.fuzztest_flags = std::move(fuzztest_flags);
  // Skip slow stacktrace symbolization, which could cause unexpected timeouts
  // in the tests.
  run_options.flags["symbolize_stacktrace"] = "0";
  run_options.raw_args = std::move(binary_args);
  run_options.env = WithTestSanitizerOptions(env);
  run_options.timeout = absl::Seconds(10);
  return RunBinary(BinaryPath(target_binary), run_options);
}

TEST(CompatibilityModeTest, RunsFuzzing) {
  const auto [status, stdout, stderr] = RunBinary(
      /*fuzztest_flags=*/{{"fuzz", "MySuite.PassesWithPositiveInput"}});
  SCOPED_TRACE(stderr);
  ASSERT_THAT(status, Eq(ExitCode(0)));
  // Check if fuzzing stats exist
  EXPECT_THAT(stderr, HasSubstr("Total runs:"));
}

TEST(CompatibilityModeTest, FindsAndReplaysCrash) {
  TempDir out_dir;
  std::string crash_path;
  {
    const auto [status, stdout, stderr] = RunBinary(
        /*fuzztest_flags=*/{{"fuzz", "MySuite.EnumValue"}}, /*binary_args=*/{
            {"--",
             absl::StrCat("-artifact_prefix=", out_dir.path().string(), "/")}});
    SCOPED_TRACE(stderr);
    ASSERT_THAT(status, Eq(ExitCode(111)));
    EXPECT_THAT(stderr, AllOf(HasSubstr("argument 0: Color{0}"),
                              HasSubstr("argument 1: Color{1}"),
                              HasSubstr("argument 2: Color{2}")));
    auto crash_files = ReadFileOrDirectory(out_dir.path().string());
    ASSERT_THAT(crash_files, SizeIs(1));
    crash_path = crash_files[0].path;
    ASSERT_THAT(crash_path, Not(IsEmpty()));
  }
  {
    const auto [status, stdout, stderr] =
        RunBinary(/*fuzztest_flags=*/{{"fuzz", "MySuite.EnumValue"}},
                  /*binary_args=*/{{"--", crash_path}});
    SCOPED_TRACE(stderr);
    ASSERT_THAT(status, Eq(ExitCode(111)));
    EXPECT_THAT(stderr, HasSubstr(absl::StrCat("Running: ", crash_path)));
    EXPECT_THAT(stderr, AllOf(HasSubstr("argument 0: Color{0}"),
                              HasSubstr("argument 1: Color{1}"),
                              HasSubstr("argument 2: Color{2}")));
    EXPECT_THAT(stderr, HasSubstr("Total runs: 1\n"));
  }
}

}  // namespace
}  // namespace fuzztest::internal
