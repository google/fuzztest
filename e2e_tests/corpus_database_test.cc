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

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <string>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/base/no_destructor.h"
#include "absl/log/check.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "./e2e_tests/test_binary_util.h"
#include "./fuzztest/internal/io.h"
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
  kSingleBinary,
  kWithCentipedeBinary,
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
    CHECK(temp_dir_ == nullptr);
  }

  static void RunUpdateCorpusDatabase() {
    if (temp_dir_ != nullptr) return;
    temp_dir_ = new TempDir();
    auto [status, std_out, std_err] = RunBinaryMaybeWithCentipede(
        GetCorpusDatabaseTestingBinaryPath(),
        {.fuzztest_flags = {
             {"corpus_database", GetCorpusDatabasePath()},
             {"fuzz_for", "30s"},
             {"jobs", "2"},
         }});
    *update_corpus_database_std_out_ = std::move(std_out);
    *update_corpus_database_std_err_ = std::move(std_err);
  }

  static void TearDownTestSuite() {
    delete temp_dir_;
    temp_dir_ = nullptr;
  }

  static std::string GetCorpusDatabasePath() {
    RunUpdateCorpusDatabase();
    return std::filesystem::path(temp_dir_->dirname()) / "corpus_database";
  }

  static absl::string_view GetUpdateCorpusDatabaseStdOut() {
    RunUpdateCorpusDatabase();
    return *update_corpus_database_std_out_;
  }

  static absl::string_view GetUpdateCorpusDatabaseStdErr() {
    RunUpdateCorpusDatabase();
    return *update_corpus_database_std_err_;
  }

  static RunResults RunBinaryMaybeWithCentipede(absl::string_view binary_path,
                                                const RunOptions &options) {
    switch (GetParam()) {
      case ExecutionModelParam::kSingleBinary:
        return RunBinary(binary_path, options);
      case ExecutionModelParam::kWithCentipedeBinary: {
        RunOptions actual_options;
        actual_options.env = options.env;
        actual_options.timeout = options.timeout;
        std::vector<std::string> binary_args;
        binary_args.push_back(std::string(binary_path));
        for (const auto &[key, value] : options.fuzztest_flags) {
          binary_args.push_back(CreateFuzzTestFlag(key, value));
        }
        for (const auto &[key, value] : options.flags) {
          binary_args.push_back(absl::StrCat("--", key, "=", value));
        }
        actual_options.flags = {
            {"binary", absl::StrJoin(binary_args, " ")},
            // Disable symbolization to more quickly get to fuzzing.
            {"symbolizer_path", ""},
        };
        return RunBinary(CentipedePath(), actual_options);
      }
    }
    fprintf(stderr, "Unsupported execution model!\n");
    std::abort();
  }

 private:
  static TempDir *temp_dir_;
  static absl::NoDestructor<std::string> update_corpus_database_std_out_;
  static absl::NoDestructor<std::string> update_corpus_database_std_err_;
};

TempDir *UpdateCorpusDatabaseTest::temp_dir_ = nullptr;
absl::NoDestructor<std::string>
    UpdateCorpusDatabaseTest::update_corpus_database_std_out_{};
absl::NoDestructor<std::string>
    UpdateCorpusDatabaseTest::update_corpus_database_std_err_{};

TEST_P(UpdateCorpusDatabaseTest, RunsFuzzTests) {
  EXPECT_THAT(GetUpdateCorpusDatabaseStdErr(),
              AllOf(HasSubstr("Fuzzing FuzzTest.FailsInTwoWays"),
                    HasSubstr("Fuzzing FuzzTest.FailsWithStackOverflow")));
}

TEST_P(UpdateCorpusDatabaseTest, UsesMultipleShardsForFuzzingAndDistillation) {
  EXPECT_THAT(
      GetUpdateCorpusDatabaseStdErr(),
      AllOf(HasSubstr("[S0.0] begin-fuzz"), HasSubstr("[S1.0] begin-fuzz"),
            HasSubstr("DISTILL[S.0]: Distilling to output shard 0"),
            HasSubstr("DISTILL[S.1]: Distilling to output shard 1")));
}

TEST_P(UpdateCorpusDatabaseTest, FindsAllCrashes) {
  EXPECT_THAT(
      GetUpdateCorpusDatabaseStdErr(),
      AllOf(ContainsRegex(R"re(Failure\s*: GoogleTest assertion failure)re"),
            ContainsRegex(R"re(Failure\s*: heap-buffer-overflow)re"),
            ContainsRegex(R"re(Failure\s*: stack-limit-exceeded)re")));
}

TEST_P(UpdateCorpusDatabaseTest, ResumedFuzzTestRunsForRemainingTime) {
  TempDir corpus_database;

  // 1st run that gets interrupted.
  auto [fst_status, fst_std_out, fst_std_err] = RunBinaryMaybeWithCentipede(
      GetCorpusDatabaseTestingBinaryPath(),
      {.fuzztest_flags =
           {
               {"corpus_database", corpus_database.dirname()},
               {"fuzz_for", "30s"},
           },
       .timeout = absl::Seconds(10)});

  // Adjust the fuzzing time so that only 1s remains.
  const absl::StatusOr<std::string> fuzzing_time_file =
      FindFile(corpus_database.dirname(), "fuzzing_time");
  ASSERT_TRUE(fuzzing_time_file.ok()) << fst_std_err;
  ASSERT_TRUE(WriteFile(*fuzzing_time_file, "299s"));

  // 2nd run that resumes the fuzzing.
  auto [snd_status, snd_std_out, snd_std_err] = RunBinaryMaybeWithCentipede(
      GetCorpusDatabaseTestingBinaryPath(),
      {.fuzztest_flags =
           {
               {"corpus_database", corpus_database.dirname()},
               {"fuzz_for", "300s"},
           },
       .timeout = absl::Seconds(10)});

  EXPECT_THAT(
      snd_std_err,
      // The resumed fuzz test is the first one defined in the binary.
      AllOf(HasSubstr("Resuming from the fuzz test FuzzTest.FailsInTwoWays"),
            HasSubstr("Fuzzing FuzzTest.FailsInTwoWays for 1s")));
}

TEST_P(UpdateCorpusDatabaseTest, ReplaysFuzzTestsInParallel) {
  auto [status, std_out, std_err] = RunBinaryMaybeWithCentipede(
      GetCorpusDatabaseTestingBinaryPath(),
      {.fuzztest_flags = {{"corpus_database", GetCorpusDatabasePath()},
                          {"replay_corpus_for", "inf"},
                          {"jobs", "2"}},
       .timeout = absl::Seconds(30)});

  EXPECT_THAT(
      std_err,
      AllOf(HasSubstr("Replaying FuzzTest.FailsInTwoWays"),
            HasSubstr("Replaying FuzzTest.FailsWithStackOverflow"),
            HasSubstr("[S0.0] begin-fuzz"), HasSubstr("[S1.0] begin-fuzz")));
}

INSTANTIATE_TEST_SUITE_P(
    UpdateCorpusDatabaseTestWithExecutionModel, UpdateCorpusDatabaseTest,
    testing::ValuesIn({ExecutionModelParam::kSingleBinary,
                       ExecutionModelParam::kWithCentipedeBinary}));

}  // namespace
}  // namespace fuzztest::internal
