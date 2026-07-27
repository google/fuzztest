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

#include <filesystem>  // NOLINT
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/strings/str_format.h"
#include "absl/time/clock.h"
#include "absl/time/clock_interface.h"
#include "absl/time/simulated_clock.h"
#include "absl/time/time.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/crash_deduplication_test_util.h"
#include "./centipede/crash_summary.h"
#include "./centipede/environment.h"
#include "./centipede/stop.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"
#include "./common/temp_dir.h"

namespace fuzztest::internal {
namespace {

using ::testing::AllOf;
using ::testing::AnyOf;
using ::testing::ContainsRegex;
using ::testing::EndsWith;
using ::testing::FieldsAre;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::MatchesRegex;
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

  // `isig5` has empty crash signature and should be ignored.
  auto input5_path = SetContentsAndGetPath(crashes1, "isig5", "input5");
  SetContentsAndGetPath(crash_metadata1, "isig5.sig", "");
  SetContentsAndGetPath(crash_metadata1, "isig5.desc", "desc5");

  // `isig6` has empty crash description and should be ignored.
  auto input6_path = SetContentsAndGetPath(crashes1, "isig6", "input6");
  SetContentsAndGetPath(crash_metadata1, "isig6.sig", "csig6");
  SetContentsAndGetPath(crash_metadata1, "isig6.desc", "");

  const auto crashes = GetCrashesFromWorkdir(workdir, /*total_shards=*/2);
  EXPECT_THAT(
      crashes,
      UnorderedElementsAre(
          Pair("csig1", AnyOf(FieldsAre("isig1", "desc1", input1_path),
                              FieldsAre("isig3", "desc1", input3_path))),
          Pair("csig2", FieldsAre("isig2", "desc2", input2_path))));
}

TEST(GetCrashesFromWorkdirTest, FailsOnEmptyCrashSignatureIfEnvVarSet) {
  TempDir test_dir;
  const std::string workdir_path = test_dir.path();
  WorkDir workdir{workdir_path, "binary_name", "binary_hash",
                  /*my_shard_index=*/0};

  const std::filesystem::path crashes =
      workdir.CrashReproducerDirPaths().Shard(0);
  const std::filesystem::path crash_metadata =
      workdir.CrashMetadataDirPaths().Shard(0);
  std::filesystem::create_directories(crashes);
  std::filesystem::create_directories(crash_metadata);

  auto input_path = SetContentsAndGetPath(crashes, "isig", "input");
  SetContentsAndGetPath(crash_metadata, "isig.sig", "");
  SetContentsAndGetPath(crash_metadata, "isig.desc", "desc");

  setenv("FUZZTEST_FAIL_ON_EMPTY_CRASH_METADATA", "1", /*overwrite=*/1);
  EXPECT_DEATH(GetCrashesFromWorkdir(workdir, /*total_shards=*/1),
               "Empty crash signature");
  unsetenv("FUZZTEST_FAIL_ON_EMPTY_CRASH_METADATA");
}

TEST(GetCrashesFromWorkdirTest, FailsOnEmptyCrashDescriptionIfEnvVarSet) {
  TempDir test_dir;
  const std::string workdir_path = test_dir.path();
  WorkDir workdir{workdir_path, "binary_name", "binary_hash",
                  /*my_shard_index=*/0};

  const std::filesystem::path crashes =
      workdir.CrashReproducerDirPaths().Shard(0);
  const std::filesystem::path crash_metadata =
      workdir.CrashMetadataDirPaths().Shard(0);
  std::filesystem::create_directories(crashes);
  std::filesystem::create_directories(crash_metadata);

  auto input_path = SetContentsAndGetPath(crashes, "isig", "input");
  SetContentsAndGetPath(crash_metadata, "isig.sig", "csig");
  SetContentsAndGetPath(crash_metadata, "isig.desc", "");

  setenv("FUZZTEST_FAIL_ON_EMPTY_CRASH_METADATA", "1", /*overwrite=*/1);
  EXPECT_DEATH(GetCrashesFromWorkdir(workdir, /*total_shards=*/1),
               "Empty crash description");
  unsetenv("FUZZTEST_FAIL_ON_EMPTY_CRASH_METADATA");
}

struct FileAndContents {
  std::string basename;
  std::string contents;

  template <typename Sink>
  friend void AbslStringify(Sink& sink, const FileAndContents& f) {
    absl::Format(&sink, "%s: %s", f.basename, f.contents);
  }
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

class OrganizeCrashingInputsTest : public ::testing::Test {
 protected:
  OrganizeCrashingInputsTest()
      : crashing_dir_(test_dir_.path() / "crashing"),
        regression_dir_(test_dir_.path() / "regression"),
        incubating_dir_(test_dir_.path() / "incubating"),
        new_crashes_dir_(test_dir_.path() / "new_crashes") {
    std::filesystem::create_directories(crashing_dir_);
    std::filesystem::create_directories(regression_dir_);
    std::filesystem::create_directories(incubating_dir_);
    std::filesystem::create_directories(new_crashes_dir_);
  }

  const std::filesystem::path& crashing_dir() const { return crashing_dir_; }
  const std::filesystem::path& regression_dir() const {
    return regression_dir_;
  }
  const std::filesystem::path& incubating_dir() const {
    return incubating_dir_;
  }
  const std::filesystem::path& new_crashes_dir() const {
    return new_crashes_dir_;
  }
  const Environment& env() const { return env_; }
  CrashSummary& crash_summary() { return crash_summary_; }

  absl::Status OrganizeCrashingInputs(
      const std::filesystem::path& regression_dir,
      const std::filesystem::path& crashing_dir, const Environment& env,
      CentipedeCallbacksFactory& callbacks_factory,
      const absl::flat_hash_map<std::string, CrashDetails>&
          new_crashes_by_signature,
      CrashSummary& crash_summary,
      absl::Duration regression_ttl = absl::Hours(24 * 7),
      absl::Clock& clock = absl::Clock::GetRealClock()) {
    return ::fuzztest::internal::OrganizeCrashingInputs(
        regression_dir, crashing_dir, incubating_dir_, env, callbacks_factory,
        new_crashes_by_signature, crash_summary, stop_condition_,
        regression_ttl, clock);
  }

 private:
  TempDir test_dir_;
  std::filesystem::path crashing_dir_;
  std::filesystem::path regression_dir_;
  std::filesystem::path incubating_dir_;
  std::filesystem::path new_crashes_dir_;
  Environment env_;
  CrashSummary crash_summary_{"binary_id", "fuzz_test"};
  StopCondition stop_condition_;
};

TEST_F(OrganizeCrashingInputsTest, CreatesDirectoriesIfMissing) {
  TempDir test_dir;
  const std::filesystem::path crashing_dir = test_dir.path() / "crashing";
  const std::filesystem::path regression_dir = test_dir.path() / "regression";
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{});
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir, crashing_dir, env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary())
                  .ok());

  const std::filesystem::directory_entry crashing_dir_entry{crashing_dir};
  const std::filesystem::directory_entry regression_dir_entry{regression_dir};
  EXPECT_TRUE(
      crashing_dir_entry.exists() && crashing_dir_entry.is_directory() &&
      regression_dir_entry.exists() && regression_dir_entry.is_directory());
}

TEST_F(OrganizeCrashingInputsTest, DeletesOldStyleCrashes) {
  SetContentsAndGetPath(crashing_dir(), "isig", "input");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input", {"csig", "desc"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary())
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, HasSubstr("Total crashes: 0"));
}

TEST_F(OrganizeCrashingInputsTest, KeepsNewStyleCrashFileIfSignatureUnchanged) {
  SetContentsAndGetPath(crashing_dir(), "bug-csig-isig", "input");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input", {"csig", "desc"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary())
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("bug-csig-isig", "input")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(incubating_dir()), IsEmpty());
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 1"),
                                  HasSubstr("Crash ID   : bug-csig-isig"),
                                  HasSubstr("Category   : desc"),
                                  HasSubstr("Signature  : csig"),
                                  HasSubstr("Description: desc")));
}

TEST_F(OrganizeCrashingInputsTest, AddsNewCrashIfCrashSignatureChanges) {
  SetContentsAndGetPath(crashing_dir(), "bug-csig_old-isig", "input");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input", {"csig_new", "desc"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary())
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(
                  FieldsAre("bug-csig_old-isig", "input"),
                  FieldsAre(MatchesRegex("[a-f0-9]+-csig_new-isig"), "input")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(incubating_dir()), IsEmpty());
  EXPECT_THAT(
      crash_report,
      AllOf(HasSubstr("Total crashes: 1"),
            ContainsRegex("Crash ID   : [a-f0-9]+-csig_new-isig"),
            HasSubstr("Category   : desc"), HasSubstr("Signature  : csig_new"),
            HasSubstr("Description: desc")));
}

TEST_F(OrganizeCrashingInputsTest,
       UpdatesModificationTimeForReproducibleCrashes) {
  const auto reproducible_input_path =
      SetContentsAndGetPath(crashing_dir(), "bug1-csig1-isig1", "repro1");
  const auto irreproducible_input_path =
      SetContentsAndGetPath(crashing_dir(), "bug2-csig2-isig2", "irrepro2");
  const auto reproducible_mtime_before =
      std::filesystem::last_write_time(reproducible_input_path);
  const auto irreproducible_mtime_before =
      std::filesystem::last_write_time(irreproducible_input_path);

  absl::SleepFor(absl::Seconds(1));

  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"repro1", {"csig1", "desc1"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary())
                  .ok());

  EXPECT_GT(std::filesystem::last_write_time(reproducible_input_path),
            reproducible_mtime_before);
  EXPECT_EQ(std::filesystem::last_write_time(irreproducible_input_path),
            irreproducible_mtime_before);
}

TEST_F(OrganizeCrashingInputsTest,
       KeepsOldFilesWhenDeduplicatingToSameSignature) {
  SetContentsAndGetPath(crashing_dir(), "bug1-csig1-isig1", "input1");
  SetContentsAndGetPath(crashing_dir(), "bug2-csig2-isig2", "input2");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input1", {"csig", "desc"}},
                                       {"input2", {"csig", "desc"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary())
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(
      ReadFiles(crashing_dir()),
      AnyOf(UnorderedElementsAre(
                FieldsAre("bug1-csig1-isig1", "input1"),
                FieldsAre("bug2-csig2-isig2", "input2"),
                FieldsAre(MatchesRegex("[a-f0-9]+-csig-isig1"), "input1")),
            UnorderedElementsAre(
                FieldsAre("bug1-csig1-isig1", "input1"),
                FieldsAre("bug2-csig2-isig2", "input2"),
                FieldsAre(MatchesRegex("[a-f0-9]+-csig-isig2"), "input2"))));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(
      crash_report,
      AllOf(HasSubstr("Total crashes: 1"), HasSubstr("Category   : desc"),
            HasSubstr("Signature  : csig"), HasSubstr("Description: desc")));
}

TEST_F(OrganizeCrashingInputsTest, KeepsFlakyCrashAndUpdatesModificationTime) {
  const auto input_path =
      SetContentsAndGetPath(crashing_dir(), "bug-csig-isig", "input");
  const auto mtime_before = std::filesystem::last_write_time(input_path);

  absl::SleepFor(absl::Seconds(1));

  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{});
  NonOwningCallbacksFactory factory(callbacks);

  absl::flat_hash_map<std::string, CrashDetails> new_crashes_by_signature;
  const auto new_input_path =
      SetContentsAndGetPath(new_crashes_dir(), "isig", "input");
  new_crashes_by_signature["csig"] = {"isig", "desc", new_input_path};

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, new_crashes_by_signature,
                                     crash_summary())
                  .ok());
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
  EXPECT_GT(std::filesystem::last_write_time(input_path), mtime_before);
}

TEST_F(OrganizeCrashingInputsTest, KeepsIrreproducibleCrashIfTtlNotExpired) {
  SetContentsAndGetPath(crashing_dir(), "bug-csig-isig", "input");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{});
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary())
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("bug-csig-isig", "input")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(incubating_dir()), IsEmpty());
  EXPECT_THAT(crash_report, HasSubstr("Total crashes: 0"));
}

TEST_F(OrganizeCrashingInputsTest,
       MovesIrreproducibleCrashToRegressionIfTtlExpired) {
  absl::SimulatedClock clock(absl::Now());
  SetContentsAndGetPath(crashing_dir(), "bug-csig-isig", "input");
  clock.AdvanceTime(absl::Hours(25));

  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{});
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary(),
                                     /*regression_ttl=*/absl::Hours(24), clock)
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(regression_dir()),
              UnorderedElementsAre(FieldsAre("isig", "input")));
  EXPECT_THAT(crash_report, HasSubstr("Total crashes: 0"));
}

TEST_F(OrganizeCrashingInputsTest, KeepsSetupFailureCrashIfTtlNotExpired) {
  SetContentsAndGetPath(crashing_dir(), "bug-csig-isig", "input");
  FakeCentipedeCallbacks callbacks(
      env(), /*crashing_inputs=*/{
          {"input", {"csig", "SETUP FAILURE: desc"}},
      });
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary())
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("bug-csig-isig", "input")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, HasSubstr("Total crashes: 0"));
}

TEST_F(OrganizeCrashingInputsTest,
       MovesSetupFailureCrashToRegressionIfTtlExpired) {
  absl::SimulatedClock clock(absl::Now());
  SetContentsAndGetPath(crashing_dir(), "bug-csig-isig", "input");
  clock.AdvanceTime(absl::Hours(25));

  FakeCentipedeCallbacks callbacks(
      env(), /*crashing_inputs=*/{
          {"input", {"csig", "SETUP FAILURE: desc"}},
      });
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary(),
                                     /*regression_ttl=*/absl::Hours(24), clock)
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(regression_dir()),
              UnorderedElementsAre(FieldsAre("isig", "input")));
  EXPECT_THAT(crash_report, HasSubstr("Total crashes: 0"));
}

TEST_F(OrganizeCrashingInputsTest,
       DeletesIrreproducibleCrashWithMalformedFileName) {
  SetContentsAndGetPath(crashing_dir(), "invalid-name", "input");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{});
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary())
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, HasSubstr("Total crashes: 0"));
}

TEST_F(OrganizeCrashingInputsTest,
       ReplacesIrreproducibleCrashWithNewCrashOfSameSignature) {
  SetContentsAndGetPath(crashing_dir(), "bug-csig-isig1", "input1");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{});
  NonOwningCallbacksFactory factory(callbacks);

  absl::flat_hash_map<std::string, CrashDetails> new_crashes_by_signature;
  const auto input2_path =
      SetContentsAndGetPath(new_crashes_dir(), "isig2", "input2");
  new_crashes_by_signature["csig"] = {"isig2", "desc2", input2_path};

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, new_crashes_by_signature,
                                     crash_summary())
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("bug-csig-isig2", "input2")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(incubating_dir()),
              UnorderedElementsAre(FieldsAre("isig1", "input1")));
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 1"),
                                  HasSubstr("Crash ID   : bug-csig-isig2"),
                                  HasSubstr("Category   : desc2"),
                                  HasSubstr("Signature  : csig"),
                                  HasSubstr("Description: desc2")));
}

TEST_F(OrganizeCrashingInputsTest,
       ReplacesIrreproducibleCrashIfReproducedByAnotherOldInput) {
  SetContentsAndGetPath(crashing_dir(), "bug1-csig-isig1", "input1");
  SetContentsAndGetPath(crashing_dir(), "bug2-csig-isig2", "input2");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input1", {"csig", "desc1"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary())
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("bug1-csig-isig1", "input1"),
                                   FieldsAre("bug2-csig-isig1", "input1")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 2"),
                                  HasSubstr("Crash ID   : bug1-csig-isig1"),
                                  HasSubstr("Crash ID   : bug2-csig-isig1"),
                                  HasSubstr("Category   : desc1"),
                                  HasSubstr("Signature  : csig"),
                                  HasSubstr("Description: desc1")));
}

TEST_F(OrganizeCrashingInputsTest, StoresNewCrashWithUniqueCrashSignature) {
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{});
  NonOwningCallbacksFactory factory(callbacks);

  absl::flat_hash_map<std::string, CrashDetails> new_crashes_by_signature;
  const auto input_path =
      SetContentsAndGetPath(new_crashes_dir(), "isig", "input");
  new_crashes_by_signature["csig"] = {"isig", "desc", input_path};

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, new_crashes_by_signature,
                                     crash_summary())
                  .ok());
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

TEST_F(OrganizeCrashingInputsTest,
       DoesNotStoreNewCrashIfSignatureAlreadyReproduced) {
  SetContentsAndGetPath(crashing_dir(), "bug-csig-isig1", "input1");
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input1", {"csig", "desc1"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  absl::flat_hash_map<std::string, CrashDetails> new_crashes_by_signature;
  const auto input2_path =
      SetContentsAndGetPath(new_crashes_dir(), "isig2", "input2");
  new_crashes_by_signature["csig"] = {"isig2", "desc2", input2_path};

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, new_crashes_by_signature,
                                     crash_summary())
                  .ok());
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

TEST_F(OrganizeCrashingInputsTest, DoesNotProcessInputsInRegressionDir) {
  SetContentsAndGetPath(regression_dir(), "isig", "input");
  FakeCentipedeCallbacks callbacks(
      env(), /*crashing_inputs=*/{{"input", {"csig", "desc"}}});
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary())
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(regression_dir()),
              UnorderedElementsAre(FieldsAre("isig", "input")));
  EXPECT_THAT(crash_report, HasSubstr("Total crashes: 0"));
}

TEST_F(OrganizeCrashingInputsTest, AddsNewCrashesUpToFileLimit) {
  SetContentsAndGetPath(crashing_dir(), "bug1-csig1-isig1", "repro1");
  SetContentsAndGetPath(crashing_dir(), "bug2-csig2-isig2", "repro2");
  SetContentsAndGetPath(crashing_dir(), "bug3-csig3-isig3", "repro3");
  SetContentsAndGetPath(crashing_dir(), "bug4-csig4-isig4", "repro4");
  SetContentsAndGetPath(crashing_dir(), "bug5-csig5-isig5", "repro5");
  SetContentsAndGetPath(crashing_dir(), "bug6-csig6-isig6", "irrepro6");
  SetContentsAndGetPath(crashing_dir(), "bug7-csig7-isig7", "irrepro7");
  SetContentsAndGetPath(crashing_dir(), "bug8-csig8-isig8", "irrepro8");
  SetContentsAndGetPath(crashing_dir(), "bug9-csig9-isig9", "irrepro9");

  absl::flat_hash_map<std::string, CrashDetails> new_crashes_by_signature;
  const auto new10_path =
      SetContentsAndGetPath(new_crashes_dir(), "isig10", "new10");
  new_crashes_by_signature["csig10"] = {"isig10", "desc10", new10_path};
  const auto new11_path =
      SetContentsAndGetPath(new_crashes_dir(), "isig11", "new11");
  new_crashes_by_signature["csig11"] = {"isig11", "desc11", new11_path};

  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"repro1", {"csig1", "desc1"}},
                                       {"repro2", {"csig2", "desc2"}},
                                       {"repro3", {"csig3", "desc3"}},
                                       {"repro4", {"csig4", "desc4"}},
                                       {"repro5", {"csig5", "desc5"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, new_crashes_by_signature,
                                     crash_summary())
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(
                  FieldsAre("bug1-csig1-isig1", "repro1"),
                  FieldsAre("bug2-csig2-isig2", "repro2"),
                  FieldsAre("bug3-csig3-isig3", "repro3"),
                  FieldsAre("bug4-csig4-isig4", "repro4"),
                  FieldsAre("bug5-csig5-isig5", "repro5"),
                  FieldsAre("bug6-csig6-isig6", "irrepro6"),
                  FieldsAre("bug7-csig7-isig7", "irrepro7"),
                  FieldsAre("bug8-csig8-isig8", "irrepro8"),
                  FieldsAre("bug9-csig9-isig9", "irrepro9"),
                  AnyOf(FieldsAre(HasSubstr("-csig10-isig10"), "new10"),
                        FieldsAre(HasSubstr("-csig11-isig11"), "new11"))));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, HasSubstr("Total crashes: 6"));
}

TEST_F(OrganizeCrashingInputsTest, ReplacesIrreproducibleCrashAtFileLimit) {
  SetContentsAndGetPath(crashing_dir(), "bug1-csig1-isig1", "repro1");
  SetContentsAndGetPath(crashing_dir(), "bug2-csig2-isig2", "repro2");
  SetContentsAndGetPath(crashing_dir(), "bug3-csig3-isig3", "repro3");
  SetContentsAndGetPath(crashing_dir(), "bug4-csig4-isig4", "repro4");
  SetContentsAndGetPath(crashing_dir(), "bug5-csig5-isig5", "repro5");
  SetContentsAndGetPath(crashing_dir(), "bug6-csig6-isig6", "repro6");
  SetContentsAndGetPath(crashing_dir(), "bug7-csig7-isig7", "repro7");
  SetContentsAndGetPath(crashing_dir(), "bug8-csig8-isig8", "repro8");
  SetContentsAndGetPath(crashing_dir(), "bug9-csig9-isig9", "repro9");
  SetContentsAndGetPath(crashing_dir(), "bug10-csig10-isig10", "irrepro10");

  absl::flat_hash_map<std::string, CrashDetails> new_crashes_by_signature;
  const auto new11_path =
      SetContentsAndGetPath(new_crashes_dir(), "isig11", "new11");
  new_crashes_by_signature["csig10"] = {"isig11", "desc11", new11_path};

  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"repro1", {"csig1", "desc1"}},
                                       {"repro2", {"csig2", "desc2"}},
                                       {"repro3", {"csig3", "desc3"}},
                                       {"repro4", {"csig4", "desc4"}},
                                       {"repro5", {"csig5", "desc5"}},
                                       {"repro6", {"csig6", "desc6"}},
                                       {"repro7", {"csig7", "desc7"}},
                                       {"repro8", {"csig8", "desc8"}},
                                       {"repro9", {"csig9", "desc9"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, new_crashes_by_signature,
                                     crash_summary())
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("bug1-csig1-isig1", "repro1"),
                                   FieldsAre("bug2-csig2-isig2", "repro2"),
                                   FieldsAre("bug3-csig3-isig3", "repro3"),
                                   FieldsAre("bug4-csig4-isig4", "repro4"),
                                   FieldsAre("bug5-csig5-isig5", "repro5"),
                                   FieldsAre("bug6-csig6-isig6", "repro6"),
                                   FieldsAre("bug7-csig7-isig7", "repro7"),
                                   FieldsAre("bug8-csig8-isig8", "repro8"),
                                   FieldsAre("bug9-csig9-isig9", "repro9"),
                                   FieldsAre("bug10-csig10-isig11", "new11")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, AllOf(HasSubstr("Total crashes: 10"),
                                  HasSubstr("Crash ID   : bug10-csig10-isig11"),
                                  HasSubstr("Category   : desc11"),
                                  HasSubstr("Signature  : csig10"),
                                  HasSubstr("Description: desc11")));
}

TEST_F(OrganizeCrashingInputsTest,
       MovesReproducingIncubatingCrashToCrashingDir) {
  SetContentsAndGetPath(incubating_dir(), "isig1", "input1");

  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input1", {"csig", "desc"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary())
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(incubating_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(
                  FieldsAre(MatchesRegex("[a-f0-9]+-csig-isig1"), "input1")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(
      crash_report,
      AllOf(HasSubstr("Total crashes: 1"),
            ContainsRegex("Crash ID   : [a-f0-9]+-csig-isig1"),
            HasSubstr("Category   : desc"), HasSubstr("Signature  : csig"),
            HasSubstr("Description: desc")));
}

TEST_F(OrganizeCrashingInputsTest,
       KeepsIrreproducibleIncubatingCrashIfTtlNotExpired) {
  SetContentsAndGetPath(incubating_dir(), "isig1", "input1");

  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{});
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary(),
                                     /*regression_ttl=*/absl::Hours(24))
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(incubating_dir()),
              UnorderedElementsAre(FieldsAre("isig1", "input1")));
  EXPECT_THAT(ReadFiles(crashing_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(crash_report, HasSubstr("Total crashes: 0"));
}

TEST_F(OrganizeCrashingInputsTest, MovesExpiredIncubatingCrashToRegressionDir) {
  absl::SimulatedClock clock(absl::Now());
  SetContentsAndGetPath(incubating_dir(), "isig1", "input1");
  clock.AdvanceTime(absl::Hours(25));

  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{});
  NonOwningCallbacksFactory factory(callbacks);

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary(),
                                     /*regression_ttl=*/absl::Hours(24), clock)
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(ReadFiles(incubating_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(crashing_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(regression_dir()),
              UnorderedElementsAre(FieldsAre("isig1", "input1")));
  EXPECT_THAT(crash_report, HasSubstr("Total crashes: 0"));
}

TEST_F(OrganizeCrashingInputsTest,
       ReplacesCrashInputIfSignatureChangesButNewCrashWithOldSignatureExists) {
  SetContentsAndGetPath(crashing_dir(), "bug1-csig_old-isig1", "input1");

  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input1", {"csig_new", "desc_new"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  absl::flat_hash_map<std::string, CrashDetails> new_crashes_by_signature;
  const auto input2_path =
      SetContentsAndGetPath(new_crashes_dir(), "isig2", "input2");
  new_crashes_by_signature["csig_old"] = {"isig2", "desc_old", input2_path};

  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, new_crashes_by_signature,
                                     crash_summary())
                  .ok());
  std::string crash_report;
  crash_summary().Report(&crash_report);

  EXPECT_THAT(
      ReadFiles(crashing_dir()),
      UnorderedElementsAre(
          FieldsAre("bug1-csig_old-isig2", "input2"),
          FieldsAre(MatchesRegex("[a-f0-9]+-csig_new-isig1"), "input1")));
  EXPECT_THAT(ReadFiles(regression_dir()), IsEmpty());
  EXPECT_THAT(ReadFiles(incubating_dir()), IsEmpty());
  EXPECT_THAT(crash_report,
              AllOf(HasSubstr("Total crashes: 2"),
                    HasSubstr("Crash ID   : bug1-csig_old-isig2"),
                    ContainsRegex("Crash ID   : [a-f0-9]+-csig_new-isig1"),
                    HasSubstr("Signature  : csig_old"),
                    HasSubstr("Signature  : csig_new")));
}

TEST_F(OrganizeCrashingInputsTest, ReplacesInputWithWinnerAlreadyOnDisk) {
  // Setup two existing crashes for the same bug/signature.
  SetContentsAndGetPath(crashing_dir(), "bug1-sig1-isig1", "input1");
  SetContentsAndGetPath(crashing_dir(), "bug1-sig1-isig2", "input2");

  // input1 reproduces with sig1 (winner).
  // input2 does not reproduce.
  FakeCentipedeCallbacks callbacks(env(), /*crashing_inputs=*/{
                                       {"input1", {"sig1", "desc1"}},
                                   });
  NonOwningCallbacksFactory factory(callbacks);

  // This should not fail with "filesystem::copy() failed" (self-copy).
  ASSERT_TRUE(OrganizeCrashingInputs(regression_dir(), crashing_dir(), env(),
                                     factory, /*new_crashes_by_signature=*/{},
                                     crash_summary())
                  .ok());

  // bug1-sig1-isig1 should be kept.
  // bug1-sig1-isig2 should be demoted to incubating.
  EXPECT_THAT(ReadFiles(crashing_dir()),
              UnorderedElementsAre(FieldsAre("bug1-sig1-isig1", "input1")));
  EXPECT_THAT(ReadFiles(incubating_dir()),
              UnorderedElementsAre(FieldsAre("isig2", "input2")));
}

}  // namespace
}  // namespace fuzztest::internal
