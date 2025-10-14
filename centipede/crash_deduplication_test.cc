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
using ::testing::Not;
using ::testing::Pair;
using ::testing::UnorderedElementsAre;

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

  WriteToLocalFile((crashes0 / "isig1").c_str(), "input1");
  WriteToLocalFile((crash_metadata0 / "isig1.sig").c_str(), "csig1");
  WriteToLocalFile((crash_metadata0 / "isig1.desc").c_str(), "desc1");

  WriteToLocalFile((crashes1 / "isig2").c_str(), "input2");
  WriteToLocalFile((crash_metadata1 / "isig2.sig").c_str(), "csig2");
  WriteToLocalFile((crash_metadata1 / "isig2.desc").c_str(), "desc2");

  WriteToLocalFile((crashes1 / "isig3").c_str(), "input3");
  WriteToLocalFile((crash_metadata1 / "isig3.sig").c_str(), "csig1");
  WriteToLocalFile((crash_metadata1 / "isig3.desc").c_str(), "desc1");

  const auto crashes = GetCrashesFromWorkdir(workdir, /*total_shards=*/2);
  EXPECT_THAT(
      crashes,
      UnorderedElementsAre(
          Pair("csig1",
               AnyOf(
                   FieldsAre("isig1", "desc1", (crashes0 / "isig1").string()),
                   FieldsAre("isig3", "desc1", (crashes1 / "isig3").string()))),
          Pair("csig2",
               FieldsAre("isig2", "desc2", (crashes1 / "isig2").string()))));
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

TEST(OrganizeOldInputsAndStoreNewCrashesTest,
     CorrectlyOrganizesOldInputsAndDeduplicatesNewCrashes) {
  TempDir test_dir;
  const std::filesystem::path crashing_dir = test_dir.path() / "crashing";
  const std::filesystem::path regression_dir = test_dir.path() / "regression";
  const std::filesystem::path new_crashes_dir = test_dir.path() / "new_crashes";
  std::filesystem::create_directories(crashing_dir);
  std::filesystem::create_directories(regression_dir);
  std::filesystem::create_directories(new_crashes_dir);

  // 1. Reproducible crash with old-style filename.
  WriteToLocalFile((crashing_dir / "isig1").c_str(), "repro1");
  // 2. Reproducible crash with new-style filename, crash signature unchanged.
  WriteToLocalFile((crashing_dir / "bug2-csig2-isig2").c_str(), "repro2");
  // 3. Reproducible crash with new-style filename, crash signature changed.
  WriteToLocalFile((crashing_dir / "bug3-csig3_old-isig3").c_str(), "repro3");
  // 4. Irreproducible input, crash signature appears among new crashes.
  WriteToLocalFile((crashing_dir / "bug4-csig4-isig4").c_str(), "irrepro4");
  // 5. Irreproducible input, but its crash signature is reproduced by another
  // input (`repro2` with `csig2`).
  WriteToLocalFile((crashing_dir / "bug5-csig2-isig5").c_str(), "irrepro5");
  // 6. Irreproducible input, crash signature is not covered by any new crashes.
  WriteToLocalFile((crashing_dir / "bug6-csig6-isig6").c_str(), "irrepro6");
  // 7. Input with malformed filename.
  WriteToLocalFile((crashing_dir / "invalid-name").c_str(), "irrepro7");
  // 8. Input that becomes irreproducible because the crash is not ordinary.
  WriteToLocalFile((crashing_dir / "bug8-csig8-isig8").c_str(), "irrepro8");
  // 9. Regression that remains irreproducible.
  WriteToLocalFile((regression_dir / "bug9-csig9-isig9").c_str(), "irrepro9");
  // 10. Regression that becomes reproducible.
  WriteToLocalFile((regression_dir / "bug10-csig10-isig10").c_str(), "repro10");

  absl::flat_hash_map<std::string, CrashDetails> new_crashes;
  // 11. New crash with a unique signature.
  const std::string new11_path = new_crashes_dir / "isig11";
  WriteToLocalFile(new11_path, "new11");
  new_crashes["csig11"] = {"isig11", "desc11", new11_path};
  // 12. New crash whose signature is already covered by `repro2`.
  const std::string new12_path = new_crashes_dir / "isig12";
  WriteToLocalFile(new12_path, "new12");
  new_crashes["csig2"] = {"isig12", "desc12", new12_path};
  // 13. New crash whose signature matches an existing regression `irrepro4`.
  const std::string new13_path = new_crashes_dir / "isig13";
  WriteToLocalFile(new13_path, "new13");
  new_crashes["csig4"] = {"isig13", "desc13", new13_path};

  Environment env;
  FakeCentipedeCallbacks callbacks(
      env, /*crashing_inputs=*/{
          {"repro1", {"csig1", "desc1"}},
          {"repro2", {"csig2", "desc2"}},
          {"repro3", {"csig3_new", "desc3"}},
          {"irrepro8", {"csig8", "SETUP FAILURE: desc8"}},
          {"repro10", {"csig10", "desc10"}},
      });
  NonOwningCallbacksFactory factory(callbacks);
  CrashSummary crash_summary{"binary_id", "fuzz_test"};

  OrganizeOldInputsAndStoreNewCrashes(regression_dir, crashing_dir, env,
                                      factory, new_crashes, crash_summary);
  std::string crash_report;
  crash_summary.Report(&crash_report);

  EXPECT_THAT(
      ReadFiles(crashing_dir),
      UnorderedElementsAre(FieldsAre("isig1-csig1-isig1", "repro1"),
                           FieldsAre("bug2-csig2-isig2", "repro2"),
                           FieldsAre("bug3-csig3_new-isig3", "repro3"),
                           FieldsAre("bug5-csig2-isig2", "repro2"),
                           FieldsAre("bug10-csig10-isig10", "repro10"),
                           FieldsAre(EndsWith("-csig11-isig11"), "new11"),
                           FieldsAre(EndsWith("-csig4-isig13"), "new13")));
  EXPECT_THAT(ReadFiles(regression_dir),
              UnorderedElementsAre(FieldsAre("bug6-csig6-isig6", "irrepro6"),
                                   FieldsAre("bug8-csig8-isig8", "irrepro8"),
                                   FieldsAre("bug9-csig9-isig9", "irrepro9")));
  EXPECT_THAT(crash_report,
              AllOf(HasSubstr("Total crashes: 7"),
                    HasSubstr("Crash ID   : isig1-csig1-isig1"),
                    HasSubstr("Category   : desc1"),  //
                    HasSubstr("Signature  : csig1"),  //
                    HasSubstr("Description: desc1"),
                    HasSubstr("Crash ID   : bug2-csig2-isig2"),
                    HasSubstr("Category   : desc2"),  //
                    HasSubstr("Signature  : csig2"),  //
                    HasSubstr("Description: desc2"),
                    HasSubstr("Crash ID   : bug3-csig3_new-isig3"),
                    HasSubstr("Category   : desc3"),
                    HasSubstr("Signature  : csig3_new"),
                    HasSubstr("Description: desc3"),
                    HasSubstr("Crash ID   : bug5-csig2-isig2"),
                    HasSubstr("Category   : desc2"),  //
                    HasSubstr("Signature  : csig2"),  //
                    HasSubstr("Description: desc2"),
                    HasSubstr("Crash ID   : bug10-csig10-isig10"),
                    HasSubstr("Category   : desc10"),  //
                    HasSubstr("Signature  : csig10"),
                    HasSubstr("Description: desc10"),  //
                    HasSubstr("-csig11-isig11"),
                    HasSubstr("Category   : desc11"),  //
                    HasSubstr("Signature  : csig11"),
                    HasSubstr("Description: desc11"),  //
                    HasSubstr("-csig4-isig13"),        //
                    HasSubstr("Category   : desc13"),  //
                    HasSubstr("Signature  : csig4"),   //
                    HasSubstr("Description: desc13")));
}

}  // namespace
}  // namespace fuzztest::internal
