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

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"
#include "./common/temp_dir.h"

namespace fuzztest::internal {
namespace {

using ::testing::AnyOf;
using ::testing::FieldsAre;
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

  // `isig4` lacks `.sig` and `.desc` files and should be ignored.
  WriteToLocalFile((crashes1 / "isig4").c_str(), "input4");

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

}  // namespace
}  // namespace fuzztest::internal
