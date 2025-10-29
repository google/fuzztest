// Copyright 2025 The Centipede Authors.
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

#include "./centipede/crash_deduplication.h"

#include <cstdlib>
#include <filesystem>  // NOLINT
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status_matchers.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/crash_summary.h"
#include "./centipede/environment.h"
#include "./centipede/runner_result.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"
#include "./common/defs.h"
#include "./common/temp_dir.h"

namespace fuzztest::internal {
namespace {

using ::absl_testing::IsOk;
using ::absl_testing::IsOkAndHolds;
using ::testing::AllOf;
using ::testing::AnyOf;
using ::testing::EndsWith;
using ::testing::FieldsAre;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;

std::string SetContentsAndGetPath(const std::filesystem::path& dir,
                                  std::string_view file_name,
                                  std::string_view contents) {
  const std::string file_path = dir / file_name;
  WriteToLocalFile(file_path, contents);
  return file_path;
}

TEST(GetCrashesFromWorkdirTest, ReturnsOneCrashPerCrashSignature) {
  TempDir test_dir;
  const std::string workdir_path = test_dir.path();
  WorkDir workdir{workdir_path, "binary_name", "binary_hash",
                  /*my_shard_index=*/0};

  const std::filesystem::path crashes0 =
      workdir.CrashReproducerDirPaths().Shard(0);
  const std::filesystem::path crash_metadata0 =
      workdir.CrashMetadataDirPaths().Shard(0);
  const std::filesystem::path crashes1 =
      workdir.CrashReproducerDirPaths().Shard(1);
  const std::filesystem::path crash_metadata1 =
      workdir.CrashMetadataDirPaths().Shard(1);
  std::filesystem::create_directories(crashes0);
  std::filesystem::create_directories(crash_metadata0);
  std::filesystem::create_directories(crashes1);
  std::filesystem::create_directories(crash_metadata1);

  auto input1_path = SetContentsAndGetPath(crashes0, "isig1", "input1");
  SetContentsAndGetPath(crash_metadata0, "isig1.sig", "csig1");
  SetContentsAndGetPath(crash_metadata0, "isig1.desc", "desc1");

  auto input2_path = SetContentsAndGetPath(crashes1, "isig2", "input2");
  SetContentsAndGetPath(crash_metadata1, "isig2.sig", "csig2");
  SetContentsAndGetPath(crash_metadata1, "isig2.desc", "desc2");

  auto input3_path = SetContentsAndGetPath(crashes1, "isig3", "input3");
  SetContentsAndGetPath(crash_metadata1, "isig3.sig", "csig1");
  SetContentsAndGetPath(crash_metadata1, "isig3.desc", "desc1");

  // `isig4` lacks `.sig` and `.desc` files and should be ignored.
  SetContentsAndGetPath(crashes1, "isig4", "input4");

  const auto crashes = GetCrashesFromWorkdir(workdir, /*total_shards=*/2);
  EXPECT_THAT(
      crashes,
      UnorderedElementsAre(
          Pair("csig1", AnyOf(FieldsAre("isig1", "desc1", input1_path),
                              FieldsAre("isig3", "desc1", input3_path))),
          Pair("csig2", FieldsAre("isig2", "desc2", input2_path))));
}

TEST(GetInputFileComponentsTest, ParsesFileNameWithOnlyInputSignature) {
  EXPECT_THAT(GetInputFileComponents("input_signature"),
              IsOkAndHolds(FieldsAre(/*bug_id=*/"input_signature",
                                     /*crash_signature=*/"",
                                     /*input_signature=*/"input_signature")));
}

TEST(GetInputFileComponentsTest, FailsOnInvalidFileName) {
  EXPECT_THAT(GetInputFileComponents("single-dash"), Not(IsOk()));
}

TEST(GetInputFileComponentsTest, ParsesFileNameWithAllComponents) {
  EXPECT_THAT(
      GetInputFileComponents("id-with-dash-crash_signature-input_signature"),
      IsOkAndHolds(FieldsAre(/*bug_id=*/"id-with-dash",
                             /*crash_signature=*/"crash_signature",
                             /*input_signature=*/"input_signature")));
}

class FakeCentipedeCallbacks : public CentipedeCallbacks {
 public:
  struct Crash {
    std::string signature;
    std::string description;
  };

  explicit FakeCentipedeCallbacks(
      const Environment& env,
      absl::flat_hash_map<std::string, Crash> crashing_inputs)
      : CentipedeCallbacks(env), crashing_inputs_(std::move(crashing_inputs)) {}

  bool Execute(std::string_view binary, const std::vector<ByteArray>& inputs,
               BatchResult& batch_result) override {
    batch_result.ClearAndResize(inputs.size());
    for (ByteSpan input : inputs) {
      auto it = crashing_inputs_.find(AsStringView(input));
      if (it == crashing_inputs_.end()) continue;
      batch_result.exit_code() = EXIT_FAILURE;
      batch_result.failure_signature() = it->second.signature;
      batch_result.failure_description() = it->second.description;
      return false;
    }
    return true;
  }

 private:
  absl::flat_hash_map<std::string, Crash> crashing_inputs_;
};

struct FileAndContents {
  std::string basename;
  std::string contents;
};

std::vector<FileAndContents> ReadFiles(const std::filesystem::path& dir) {
  std::vector<FileAndContents> files;
  for (const auto& f : std::filesystem::directory_iterator(dir)) {
    std::string contents;
    ReadFromLocalFile(f.path().c_str(), contents);
    files.push_back(FileAndContents{std::filesystem::path(f).filename(),
                                    std::move(contents)});
  }
  return files;
}

class OrganizeInputsTest : public ::testing::Test {
 protected:
  OrganizeInputsTest()
      : crashing_dir_(test_dir_.path() / "crashing"),
        regression_dir_(test_dir_.path() / "regression"),
        new_crashes_dir_(test_dir_.path() / "new_crashes") {
    std::filesystem::create_directories(crashing_dir_);
    std::filesystem::create_directories(regression_dir_);
    std::filesystem::create_directories(new_crashes_dir_);
  }

  const std::filesystem::path& crashing_dir() const { return crashing_dir_; }
  const std::filesystem::path& regression_dir() const {
    return regression_dir_;
  }
  const std::filesystem::path& new_crashes_dir() const {
    return new_crashes_dir_;
  }
  const Environment& env() const { return env_; }
  CrashSummary& crash_summary() { return crash_summary_; }

 private:
  TempDir test_dir_;
  std::filesystem::path crashing_dir_;
  std::filesystem::path regression_dir_;
  std::filesystem::path new_crashes_dir_;
  Environment env_;
  CrashSummary crash_summary_{"binary_id", "fuzz_test"};
};

TEST_F(OrganizeInputsTest, RenamesOldStyleCrashFileToNewStyle) {
  SetContentsAndGetPath(crashing_dir(), "isig", "input");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input", {"csig", "desc"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory,
                                      /*new_crashes=*/{}, crash_summary());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("isig-csig-isig", "input")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 1"),
                                  HasSubstr("Crash ID   : isig-csig-isig"),
                                  HasSubstr("Category   : desc"),
                                  HasSubstr("Signature  : csig"),
                                  HasSubstr("Description: desc")));
}

TEST_F(OrganizeInputsTest, KeepsNewStyleCrashFileIfSignatureUnchanged) {
  SetContentsAndGetPath(crashing_dir(), "bug-csig-isig", "input");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input", {"csig", "desc"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory,
                                      /*new_crashes=*/{}, crash_summary());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("bug-csig-isig", "input")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 1"),
                                  HasSubstr("Crash ID   : bug-csig-isig"),
                                  HasSubstr("Category   : desc"),
                                  HasSubstr("Signature  : csig"),
                                  HasSubstr("Description: desc")));
}

TEST_F(OrganizeInputsTest, UpdatesCrashSignatureInFileNameIfChanged) {
  SetContentsAndGetPath(crashing_dir(), "bug-csig_old-isig", "input");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input", {"csig_new", "desc"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory,
                                      /*new_crashes=*/{}, crash_summary());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("bug-csig_new-isig", "input")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 1"),
                                  HasSubstr("Crash ID   : bug-csig_new-isig"),
                                  HasSubstr("Category   : desc"),
                                  HasSubstr("Signature  : csig_new"),
                                  HasSubstr("Description: desc")));
}

TEST_F(OrganizeInputsTest, MovesReproducibleRegressionToCrashingDir) {
  SetContentsAndGetPath(regression_dir(), "bug-csig-isig", "input");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input", {"csig", "desc"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory,
                                      /*new_crashes=*/{}, crash_summary());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("bug-csig-isig", "input")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 1"),
                                  HasSubstr("Crash ID   : bug-csig-isig"),
                                  HasSubstr("Category   : desc"),
                                  HasSubstr("Signature  : csig"),
                                  HasSubstr("Description: desc")));
}

TEST_F(OrganizeInputsTest, MovesIrreproducibleCrashToRegressionDir) {
  SetContentsAndGetPath(crashing_dir(), "bug-csig-isig", "input");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{});
  NonOwningCallbacksFactory factory(callbacks);

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory,
                                      /*new_crashes=*/{}, crash_summary());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(regression_dir()),
              UnorderedElementsAre(FieldsAre("bug-csig-isig", "input")));
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 0")));
}

TEST_F(OrganizeInputsTest, KeepsIrreproducibleRegressionInRegressionDir) {
  SetContentsAndGetPath(regression_dir(), "bug-csig-isig", "input");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{});
  NonOwningCallbacksFactory factory(callbacks);

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory,
                                      /*new_crashes=*/{}, crash_summary());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(regression_dir()),
              UnorderedElementsAre(FieldsAre("bug-csig-isig", "input")));
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 0")));
}

TEST_F(OrganizeInputsTest, MovesSetupFailureCrashToRegressionDir) {
  SetContentsAndGetPath(crashing_dir(), "bug-csig-isig", "input");
  FakeCentipedeCallbacks callbacks(
      env(), /*crashing_inputs=*/{
          {"input", {"csig", "SETUP FAILURE: desc"}},
      });
  NonOwningCallbacksFactory factory(callbacks);

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory,
                                      /*new_crashes=*/{}, crash_summary());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(regression_dir()),
              UnorderedElementsAre(FieldsAre("bug-csig-isig", "input")));
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 0")));
}

TEST_F(OrganizeInputsTest, DeletesIrreproducibleCrashWithMalformedFileName) {
  SetContentsAndGetPath(crashing_dir(), "invalid-name", "input");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{});
  NonOwningCallbacksFactory factory(callbacks);

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory,
                                      /*new_crashes=*/{}, crash_summary());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 0")));
}

TEST_F(OrganizeInputsTest,
       ReplacesIrreproducibleCrashWithNewCrashOfSameSignature) {
  SetContentsAndGetPath(crashing_dir(), "bug-csig-isig1", "input1");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{});
  NonOwningCallbacksFactory factory(callbacks);

  absl::flat_hash_map<std::string, CrashDetails> new_crashes;
  const auto input2_path =
      SetContentsAndGetPath(new_crashes_dir(), "isig2", "input2");
  new_crashes["csig"] = {"isig2", "desc2", input2_path};

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory, new_crashes, crash_summary());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("bug-csig-isig2", "input2")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 1"),
                                  HasSubstr("Crash ID   : bug-csig-isig2"),
                                  HasSubstr("Category   : desc2"),
                                  HasSubstr("Signature  : csig"),
                                  HasSubstr("Description: desc2")));
}

TEST_F(OrganizeInputsTest,
       ReplacesIrreproducibleRegressionWithNewCrashOfSameSignature) {
  SetContentsAndGetPath(regression_dir(), "bug-csig-isig1", "input1");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{});
  NonOwningCallbacksFactory factory(callbacks);

  absl::flat_hash_map<std::string, CrashDetails> new_crashes;
  const auto input2_path =
      SetContentsAndGetPath(new_crashes_dir(), "isig2", "input2");
  new_crashes["csig"] = {"isig2", "desc2", input2_path};

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory, new_crashes, crash_summary());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("bug-csig-isig2", "input2")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 1"),
                                  HasSubstr("Crash ID   : bug-csig-isig2"),
                                  HasSubstr("Category   : desc2"),
                                  HasSubstr("Signature  : csig"),
                                  HasSubstr("Description: desc2")));
}

TEST_F(OrganizeInputsTest,
       MovesIrreproducibleCrashToRegressionDirIfReproducedByAnotherOldInput) {
  SetContentsAndGetPath(crashing_dir(), "bug1-csig-isig1", "input1");
  SetContentsAndGetPath(crashing_dir(), "bug2-csig-isig2", "input2");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input1", {"csig", "desc1"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory,
                                      /*new_crashes=*/{}, crash_summary());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("bug1-csig-isig1", "input1")));
  EXPECT_THAT(ReadFiles(regression_dir()),
              UnorderedElementsAre(FieldsAre("bug2-csig-isig2", "input2")));
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 1"),
                                  HasSubstr("Crash ID   : bug1-csig-isig1"),
                                  HasSubstr("Category   : desc1"),
                                  HasSubstr("Signature  : csig"),
                                  HasSubstr("Description: desc1")));
}

TEST_F(OrganizeInputsTest, StoresNewCrashWithUniqueCrashSignature) {
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{});
  NonOwningCallbacksFactory factory(callbacks);

  absl::flat_hash_map<std::string, CrashDetails> new_crashes;
  const auto input_path =
      SetContentsAndGetPath(new_crashes_dir(), "isig", "input");
  new_crashes["csig"] = {"isig", "desc", input_path};

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory, new_crashes, crash_summary());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre(EndsWith("-csig-isig"), "input")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report,
              AllOf(HasSubstr("Total crashes: 1"),   //
                    HasSubstr("-csig-isig"),         //
                    HasSubstr("Category   : desc"),  //
                    HasSubstr("Signature  : csig"),  //
                    HasSubstr("Description: desc")));
}

TEST_F(OrganizeInputsTest, DoesNotStoreNewCrashIfSignatureAlreadyReproduced) {
  SetContentsAndGetPath(crashing_dir(), "bug-csig-isig1", "input1");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input1", {"csig", "desc1"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  absl::flat_hash_map<std::string, CrashDetails> new_crashes;
  const auto input2_path =
      SetContentsAndGetPath(new_crashes_dir(), "isig2", "input2");
  new_crashes["csig"] = {"isig2", "desc2", input2_path};

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory, new_crashes, crash_summary());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("bug-csig-isig1", "input1")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 1"),
                                  HasSubstr("Crash ID   : bug-csig-isig1"),
                                  HasSubstr("Category   : desc1"),
                                  HasSubstr("Signature  : csig"),
                                  HasSubstr("Description: desc1")));
}

TEST_F(OrganizeInputsTest,
       MovesReproducibleRegressionsWithSameSignatureToCrashingDir) {
  SetContentsAndGetPath(regression_dir(), "bug1-csig1-isig1", "input1");
  SetContentsAndGetPath(regression_dir(), "bug2-csig2-isig2", "input2");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input1", {"csig", "desc"}},
                                       {"input2", {"csig", "desc"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory,
                                      /*new_crashes=*/{}, crash_summary());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("bug1-csig-isig1", "input1"),
                                   FieldsAre("bug2-csig-isig2", "input2")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 2"),
                                  HasSubstr("Crash ID   : bug1-csig-isig1"),
                                  HasSubstr("Crash ID   : bug2-csig-isig2"),
                                  HasSubstr("Category   : desc"),
                                  HasSubstr("Signature  : csig"),
                                  HasSubstr("Description: desc")));
}

TEST_F(OrganizeInputsTest, AddsNewCrashesUpToFileLimit) {
  SetContentsAndGetPath(crashing_dir(), "bug1-csig1-isig1", "repro1");
  SetContentsAndGetPath(crashing_dir(), "bug2-csig2-isig2", "repro2");
  SetContentsAndGetPath(crashing_dir(), "bug3-csig3-isig3", "repro3");
  SetContentsAndGetPath(crashing_dir(), "bug4-csig4-isig4", "repro4");
  SetContentsAndGetPath(crashing_dir(), "bug5-csig5-isig5", "repro5");
  SetContentsAndGetPath(regression_dir(), "bug6-csig6-isig6", "irrepro6");
  SetContentsAndGetPath(regression_dir(), "bug7-csig7-isig7", "irrepro7");
  SetContentsAndGetPath(regression_dir(), "bug8-csig8-isig8", "irrepro8");
  SetContentsAndGetPath(regression_dir(), "bug9-csig9-isig9", "irrepro9");

  absl::flat_hash_map<std::string, CrashDetails> new_crashes;
  const auto new10_path =
      SetContentsAndGetPath(new_crashes_dir(), "isig10", "new10");
  new_crashes["csig10"] = {"isig10", "desc10", new10_path};
  const auto new11_path =
      SetContentsAndGetPath(new_crashes_dir(), "isig11", "new11");
  new_crashes["csig11"] = {"isig11", "desc11", new11_path};

  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"repro1", {"csig1", "desc1"}},
                                       {"repro2", {"csig2", "desc2"}},
                                       {"repro3", {"csig3", "desc3"}},
                                       {"repro4", {"csig4", "desc4"}},
                                       {"repro5", {"csig5", "desc5"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory, new_crashes, crash_summary());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(
                  FieldsAre("bug1-csig1-isig1", "repro1"),
                  FieldsAre("bug2-csig2-isig2", "repro2"),
                  FieldsAre("bug3-csig3-isig3", "repro3"),
                  FieldsAre("bug4-csig4-isig4", "repro4"),
                  FieldsAre("bug5-csig5-isig5", "repro5"),
                  AnyOf(FieldsAre(HasSubstr("-csig10-isig10"), "new10"),
                        FieldsAre(HasSubstr("-csig11-isig11"), "new11"))));
  EXPECT_THAT(ReadFiles(regression_dir()),
              UnorderedElementsAre(FieldsAre("bug6-csig6-isig6", "irrepro6"),
                                   FieldsAre("bug7-csig7-isig7", "irrepro7"),
                                   FieldsAre("bug8-csig8-isig8", "irrepro8"),
                                   FieldsAre("bug9-csig9-isig9", "irrepro9")));
  EXPECT_THAT(crash_report, HasSubstr("Total crashes: 6"));
}

TEST_F(OrganizeInputsTest, UpdatesModificationTimeForReproducibleCrashes) {
  const auto crashing_input_path =
      SetContentsAndGetPath(crashing_dir(), "bug1-csig1-isig1", "repro1");
  const auto regression_input_path =
      SetContentsAndGetPath(regression_dir(), "bug2-csig2-isig2", "irrepro2");
  const auto crashing_mtime_before =
      std::filesystem::last_write_time(crashing_input_path);
  const auto regression_mtime_before =
      std::filesystem::last_write_time(regression_input_path);

  // Sleep for 1 sec to ensure we can detect mtime change, as filesystem mtime
  // resolution might be 1 second.
  absl::SleepFor(absl::Seconds(1));

  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"repro1", {"csig1", "desc1"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  OrganizeOldInputsAndStoreNewCrashes(regression_dir(), crashing_dir(), env(),
                                      factory,
                                      /*new_crashes=*/{}, crash_summary());

  EXPECT_GT(std::filesystem::last_write_time(crashing_input_path),
            crashing_mtime_before);
  EXPECT_EQ(std::filesystem::last_write_time(regression_input_path),
            regression_mtime_before);
}

}  // namespace
}  // namespace fuzztest::internal
