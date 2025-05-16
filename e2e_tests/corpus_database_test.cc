// Copyright 2024 Google LLC
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

#include <filesystem>  // NOLINT
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/container/flat_hash_map.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "./common/temp_dir.h"
#include "./e2e_tests/test_binary_util.h"
#include "./fuzztest/internal/escaping.h"
#include "./fuzztest/internal/io.h"
#include "./fuzztest/internal/logging.h"
#include "./fuzztest/internal/subprocess.h"

namespace fuzztest::internal {
namespace {

using ::testing::ContainsRegex;
using ::testing::Eq;
using ::testing::HasSubstr;

std::string GetCorpusDatabaseTestingBinaryPath() {
  return BinaryPath((std::filesystem::path("testdata") /
                     "fuzz_tests_for_corpus_database_testing")
                        .c_str());
}

absl::StatusOr<std::string> FindFile(absl::string_view root_path,
                                     absl::string_view file_name) {
  for (const std::string &path : ListDirectoryRecursively(root_path)) {
    if (std::filesystem::path(path).filename() == file_name) return path;
  }
  return absl::NotFoundError(absl::StrCat("File ", file_name, " not found."));
}

enum class ExecutionModelParam {
  kTestBinary,
  kTestBinaryInvokingCentipedeBinary,
  kCentipedeBinary
};

struct UpdateCorpusDatabaseRun {
  std::unique_ptr<TempDir> workspace;
  std::string std_err;
};

class UpdateCorpusDatabaseTest
    : public ::testing::TestWithParam<ExecutionModelParam> {
 protected:
  static void SetUpTestSuite() {
#if defined(__has_feature)
#if !__has_feature(address_sanitizer)
    CHECK(false) << "The test binary is not built with ASAN. Please run with "
                    "--config=asan.";
#elif !__has_feature(coverage_sanitizer) || !defined(FUZZTEST_USE_CENTIPEDE)
    CHECK(false) << "The test binary is not built with coverage "
                    "instrumentation for Centipede. "
    "Please run with --config=fuzztest-experimental.";
#endif
#endif
  }

  static void RunUpdateCorpusDatabase() {
    if (run_map_->contains(GetParam())) return;
    auto &run = (*run_map_)[GetParam()];
    run.workspace = std::make_unique<TempDir>();
    RunOptions run_options;
    run_options.fuzztest_flags = {
        {"corpus_database", GetCorpusDatabasePath()},
        {"fuzz_for", "30s"},
        {"jobs", "2"},
    };
    auto [status_unused, std_out_unused, std_err] = RunBinaryMaybeWithCentipede(
        GetCorpusDatabaseTestingBinaryPath(), run_options);
    run.std_err = std::move(std_err);
  }

  static void TearDownTestSuite() { run_map_->clear(); }

  static std::string GetCorpusDatabasePath() {
    RunUpdateCorpusDatabase();
    return (*run_map_)[GetParam()].workspace->path() / "corpus_database";
  }

  static absl::string_view GetUpdateCorpusDatabaseStdErr() {
    RunUpdateCorpusDatabase();
    return (*run_map_)[GetParam()].std_err;
  }

  static RunResults RunBinaryMaybeWithCentipede(absl::string_view binary_path,
                                                RunOptions options) {
    // Dumping stack trace in gtest would slow down the execution, causing
    // test flakiness.
    options.flags[GTEST_FLAG_PREFIX_ "stack_trace_depth"] = "0";
    switch (GetParam()) {
      case ExecutionModelParam::kTestBinary:
        return RunBinary(binary_path, options);
      case ExecutionModelParam::kTestBinaryInvokingCentipedeBinary: {
        RunOptions centipede_options = options;
        centipede_options.fuzztest_flags["internal_centipede_command"] =
            ShellEscape(CentipedePath());
        return RunBinary(binary_path, centipede_options);
      }
      case ExecutionModelParam::kCentipedeBinary: {
        RunOptions centipede_options;
        centipede_options.env = options.env;
        centipede_options.timeout = options.timeout;
        std::vector<std::string> binary_args;
        binary_args.push_back(std::string(binary_path));
        for (const auto &[key, value] : options.fuzztest_flags) {
          binary_args.push_back(CreateFuzzTestFlag(key, value));
        }
        for (const auto &[key, value] : options.flags) {
          binary_args.push_back(absl::StrCat("--", key, "=", value));
        }
        centipede_options.flags = {
            {"binary", absl::StrJoin(binary_args, " ")},
            // Disable symbolization to more quickly get to fuzzing.
            {"symbolizer_path", ""},
        };
        return RunBinary(CentipedePath(), centipede_options);
      }
    }
    FUZZTEST_INTERNAL_CHECK(false, "Unsupported execution model!\n");
  }

 private:
  static absl::NoDestructor<
      absl::flat_hash_map<ExecutionModelParam, UpdateCorpusDatabaseRun>>
      run_map_;
};

absl::NoDestructor<
    absl::flat_hash_map<ExecutionModelParam, UpdateCorpusDatabaseRun>>
    UpdateCorpusDatabaseTest::run_map_{};

TEST_P(UpdateCorpusDatabaseTest, RunsFuzzTests) {
  EXPECT_THAT(GetUpdateCorpusDatabaseStdErr(),
              AllOf(HasSubstr("Fuzzing FuzzTest.FailsInTwoWays"),
                    HasSubstr("Fuzzing FuzzTest.FailsWithStackOverflow")));
}

TEST_P(UpdateCorpusDatabaseTest, UsesMultipleShardsForFuzzingAndDistillation) {
  const auto &std_err = GetUpdateCorpusDatabaseStdErr();
  EXPECT_THAT(
      std_err,
      AllOf(HasSubstr("[S0.0] begin-fuzz"), HasSubstr("[S1.0] begin-fuzz"),
            HasSubstr("DISTILL[S.0]: Distilling to output shard 0"),
            HasSubstr("DISTILL[S.1]: Distilling to output shard 1")))
      << std_err;
}

TEST_P(UpdateCorpusDatabaseTest, FindsAllCrashes) {
  const auto &std_err = GetUpdateCorpusDatabaseStdErr();
  EXPECT_THAT(
      std_err,
      AllOf(ContainsRegex(R"re(Failure\s*: GoogleTest assertion failure)re"),
            ContainsRegex(R"re(Failure\s*: heap-buffer-overflow)re"),
            ContainsRegex(R"re(Failure\s*: stack-limit-exceeded)re")))
      << std_err;
}

TEST_P(UpdateCorpusDatabaseTest, StartsNewFuzzTestRunsWithoutExecutionIds) {
  TempDir corpus_database;

  // 1st run that gets interrupted.
  RunOptions fst_run_options;
  fst_run_options.fuzztest_flags = {
      {"corpus_database", corpus_database.path()},
      {"fuzz_for", "300s"},
  };
  fst_run_options.timeout = absl::Seconds(10);
  auto [fst_status, fst_std_out, fst_std_err] = RunBinaryMaybeWithCentipede(
      GetCorpusDatabaseTestingBinaryPath(), fst_run_options);

  EXPECT_THAT(fst_std_err, HasSubstr("Fuzzing FuzzTest.FailsInTwoWays for 5m"));

  // Adjust the fuzzing time so that only 1s remains.
  const absl::StatusOr<std::string> fuzzing_time_file =
      FindFile(corpus_database.path().c_str(), "fuzzing_time");
  ASSERT_TRUE(fuzzing_time_file.ok()) << fst_std_err;
  ASSERT_TRUE(WriteFile(*fuzzing_time_file, "299s"));

  // 2nd run that does not resume due to no execution ID.
  RunOptions snd_run_options;
  snd_run_options.fuzztest_flags = {
      {"corpus_database", corpus_database.path()},
      {"fuzz_for", "300s"},
  };
  snd_run_options.timeout = absl::Seconds(10);
  auto [snd_status, snd_std_out, snd_std_err] = RunBinaryMaybeWithCentipede(
      GetCorpusDatabaseTestingBinaryPath(), snd_run_options);

  EXPECT_THAT(snd_std_err, HasSubstr("Fuzzing FuzzTest.FailsInTwoWays for 5m"));
}

TEST_P(UpdateCorpusDatabaseTest,
       ResumesOrSkipsFuzzTestRunsWhenStoredAndCurrentExecutionIdsMatch) {
  TempDir corpus_database;

  // 1st run that gets interrupted.
  RunOptions fst_run_options;
  fst_run_options.fuzztest_flags = {
      {"corpus_database", corpus_database.path()},
      {"fuzz_for", "300s"},
      {"execution_id", "some_execution_id"},
  };
  fst_run_options.timeout = absl::Seconds(20);
  auto [fst_status_unused, fst_std_out_unused, fst_std_err] =
      RunBinaryMaybeWithCentipede(GetCorpusDatabaseTestingBinaryPath(),
                                  fst_run_options);

  // Adjust the fuzzing time so that only 1s remains.
  const absl::StatusOr<std::string> fuzzing_time_file =
      FindFile(corpus_database.path().c_str(), "fuzzing_time");
  ASSERT_TRUE(fuzzing_time_file.ok()) << fst_std_err;
  ASSERT_TRUE(WriteFile(*fuzzing_time_file, "299s"));

  // 2nd run that should resume due to the same execution ID.
  RunOptions snd_run_options;
  snd_run_options.fuzztest_flags = {
      {"corpus_database", corpus_database.path()},
      {"fuzz_for", "300s"},
      {"execution_id", "some_execution_id"},
  };
  snd_run_options.timeout = absl::Seconds(20);
  auto [snd_status_unused, snd_std_out_unused, snd_std_err] =
      RunBinaryMaybeWithCentipede(GetCorpusDatabaseTestingBinaryPath(),
                                  snd_run_options);
  EXPECT_THAT(
      snd_std_err,
      // The resumed fuzz test is the first one defined in the binary.
      AllOf(HasSubstr("Resuming running the fuzz test FuzzTest.FailsInTwoWays"),
            HasSubstr("Fuzzing FuzzTest.FailsInTwoWays for 1s"),
            // Make sure that FailsInTwoWays finished.
            HasSubstr("Fuzzing FuzzTest.FailsWithStackOverflow")))
      << snd_std_err;

  // 3rd run that should skip the test due the test is finished in the 2nd
  // exeuction with the same ID.
  RunOptions thd_run_options;
  thd_run_options.fuzztest_flags = {
      {"corpus_database", corpus_database.path()},
      {"fuzz_for", "300s"},
      {"execution_id", "some_execution_id"},
  };
  thd_run_options.timeout = absl::Seconds(20);
  auto [thd_status_unused, thd_std_out_unused, thd_std_err] =
      RunBinaryMaybeWithCentipede(GetCorpusDatabaseTestingBinaryPath(),
                                  thd_run_options);
  EXPECT_THAT(
      thd_std_err,
      // The skipped fuzz test is the first one defined in the binary.
      HasSubstr("Skipping running the fuzz test FuzzTest.FailsInTwoWays"))
      << thd_std_err;
}

TEST_P(UpdateCorpusDatabaseTest,
       StartsNewFuzzTestRunWhenStoredAndCurrentExecutionIdsMismatch) {
  TempDir corpus_database;

  // 1st run that gets interrupted.
  RunOptions fst_run_options;
  fst_run_options.fuzztest_flags = {
      {"corpus_database", corpus_database.path()},
      {"fuzz_for", "300s"},
      {"execution_id", "some_execution_id_1"},
  };
  fst_run_options.timeout = absl::Seconds(10);
  auto [fst_status_unused, fst_std_out_unused, fst_std_err] =
      RunBinaryMaybeWithCentipede(GetCorpusDatabaseTestingBinaryPath(),
                                  fst_run_options);

  // 2nd run that should not resume due to the different execution ID.
  // This run should complete within the timeout.
  RunOptions snd_run_options;
  snd_run_options.fuzztest_flags = {
      {"corpus_database", corpus_database.path()},
      {"fuzz_for", "1s"},
      {"execution_id", "some_execution_id_2"},
  };
  snd_run_options.timeout = absl::Seconds(10);
  auto [snd_status_unused, snd_std_out_unused, snd_std_err] =
      RunBinaryMaybeWithCentipede(GetCorpusDatabaseTestingBinaryPath(),
                                  snd_run_options);
  EXPECT_THAT(snd_std_err,
              AllOf(Not(HasSubstr("Resuming running the fuzz test")),
                    HasSubstr("Starting a new run of the fuzz test")))
      << snd_std_err;

  // 3rd run that should not skip the test due the different execution ID
  RunOptions thd_run_options;
  thd_run_options.fuzztest_flags = {
      {"corpus_database", corpus_database.path()},
      {"fuzz_for", "300s"},
      {"execution_id", "some_execution_id_3"},
  };
  thd_run_options.timeout = absl::Seconds(10);
  auto [thd_status_unused, thd_std_out_unused, thd_std_err] =
      RunBinaryMaybeWithCentipede(GetCorpusDatabaseTestingBinaryPath(),
                                  thd_run_options);
  EXPECT_THAT(thd_std_err,
              AllOf(Not(HasSubstr("Skipping running the fuzz test")),
                    HasSubstr("Starting a new run of the fuzz test")))
      << thd_std_err;
}

TEST_P(UpdateCorpusDatabaseTest, ReplaysFuzzTestsInParallel) {
  RunOptions run_options;
  run_options.fuzztest_flags = {{"corpus_database", GetCorpusDatabasePath()},
                                {"replay_corpus_for", "inf"},
                                {"jobs", "2"}};
  run_options.timeout = absl::Seconds(30);
  auto [status, std_out, std_err] = RunBinaryMaybeWithCentipede(
      GetCorpusDatabaseTestingBinaryPath(), run_options);

  EXPECT_THAT(
      std_err,
      AllOf(HasSubstr("Replaying FuzzTest.FailsInTwoWays"),
            HasSubstr("Replaying FuzzTest.FailsWithStackOverflow"),
            HasSubstr("[S0.0] begin-fuzz"), HasSubstr("[S1.0] begin-fuzz")));
}

TEST_P(UpdateCorpusDatabaseTest, PrintsErrorsWhenBazelTimeoutIsNotEnough) {
  RunOptions run_options;
  run_options.fuzztest_flags = {{"corpus_database", GetCorpusDatabasePath()},
                                {"fuzz_for", "20s"}};
  run_options.env = {{"TEST_TIMEOUT", "30"}};
  run_options.timeout = absl::Seconds(60);
  auto [status, std_out, std_err] = RunBinaryMaybeWithCentipede(
      GetCorpusDatabaseTestingBinaryPath(), run_options);
  EXPECT_THAT(std_err, AllOf(HasSubstr("Fuzzing FuzzTest.FailsInTwoWays"),
                             HasSubstr("Not enough time for running the fuzz "
                                       "test FuzzTest.FailsWithStackOverflow")))
      << std_err;
}

INSTANTIATE_TEST_SUITE_P(
    UpdateCorpusDatabaseTestWithExecutionModel, UpdateCorpusDatabaseTest,
    testing::ValuesIn({ExecutionModelParam::kTestBinary,
                       ExecutionModelParam::kTestBinaryInvokingCentipedeBinary,
                       ExecutionModelParam::kCentipedeBinary}));

}  // namespace
}  // namespace fuzztest::internal
