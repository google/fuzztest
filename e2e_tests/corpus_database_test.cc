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
#include <string>
#include <utility>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/log/check.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./e2e_tests/test_binary_util.h"

namespace fuzztest::internal {
namespace {

using ::testing::HasSubstr;

class UpdateCorpusDatabaseTest : public testing::Test {
 protected:
  static void SetUpTestSuite() {
#if defined(__has_feature)
#if !__has_feature(address_sanitizer)
    GTEST_SKIP() << "Skipping the tests because the test binary is not built "
                    "with ASAN. Please run with --config=asan.";
#elif !__has_feature(coverage_sanitizer) || !defined(FUZZTEST_USE_CENTIPEDE)
    GTEST_SKIP() << "Skipping the tests because the test binary is not built "
                    "with coverage instrumentation for Centipede. "
    "Please run with --config=fuzztest-experimental.";
#endif
#endif

    temp_dir_ = new TempDir();

    auto [status, std_out, std_err] = RunBinary(
        CentipedePath(),
        {.flags = {
             {"binary",
              absl::StrCat(BinaryPath((std::filesystem::path("testdata") /
                                       "fuzz_tests_for_corpus_database_testing")
                                          .c_str()),
                           " ",
                           CreateFuzzTestFlag("corpus_database",
                                              GetCorpusDatabasePath()),
                           " ", CreateFuzzTestFlag("fuzz_for", "30s"))}}});

    centipede_std_out_ = new std::string(std::move(std_out));
    centipede_std_err_ = new std::string(std::move(std_err));
  }

  static void TearDownTestSuite() {
    delete temp_dir_;
    temp_dir_ = nullptr;
    delete centipede_std_out_;
    centipede_std_out_ = nullptr;
    delete centipede_std_err_;
    centipede_std_err_ = nullptr;
  }

  static std::string GetCorpusDatabasePath() {
    CHECK(temp_dir_ != nullptr);
    return std::filesystem::path(temp_dir_->dirname()) / "corpus_database";
  }

  static absl::string_view GetCentipedeStdOut() {
    CHECK(centipede_std_out_ != nullptr);
    return *centipede_std_out_;
  }

  static absl::string_view GetCentipedeStdErr() {
    CHECK(centipede_std_err_ != nullptr);
    return *centipede_std_err_;
  }

 private:
  static TempDir *temp_dir_;
  static std::string *centipede_std_out_;
  static std::string *centipede_std_err_;
};

TempDir *UpdateCorpusDatabaseTest::temp_dir_ = nullptr;
std::string *UpdateCorpusDatabaseTest::centipede_std_out_ = nullptr;
std::string *UpdateCorpusDatabaseTest::centipede_std_err_ = nullptr;

TEST_F(UpdateCorpusDatabaseTest, RunsFuzzTests) {
  EXPECT_THAT(GetCentipedeStdErr(),
              HasSubstr("Fuzzing FuzzTest.FailsInTwoWays"));
}

}  // namespace
}  // namespace fuzztest::internal
