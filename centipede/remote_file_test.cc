// Copyright 2023 The Centipede Authors.
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

#include "./centipede/remote_file.h"

#include <filesystem>
#include <fstream>
#include <string>
#include <string_view>
#include <vector>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "./centipede/test_util.h"

namespace centipede {
namespace {

using ::testing::IsEmpty;
using ::testing::UnorderedElementsAre;

bool CreateFile(std::string_view path) {
  std::ofstream f((std::string(path)));
  if (!f) {
    return false;
  }
  return true;
}

TEST(RemoteListFilesRecursively, ListsFilesInRecursiveDirectories) {
  auto temp_dir = std::filesystem::path(GetTestTempDir(test_info_->name()));

  auto file1_path = temp_dir / "file_01";
  ASSERT_TRUE(CreateFile(file1_path.string()));
  auto file2_path = temp_dir / "file_02";
  ASSERT_TRUE(CreateFile(file2_path.string()));

  auto dir1_path = temp_dir / "dir_01";
  std::filesystem::create_directories(dir1_path);
  auto file3_path = dir1_path / "file_03";
  ASSERT_TRUE(CreateFile(file3_path.string()));

  const std::vector<std::string> files =
      RemoteListFilesRecursively(temp_dir.string());
  EXPECT_THAT(files,
              UnorderedElementsAre(file1_path.string(), file2_path.string(),
                                   file3_path.string()));
}

TEST(RemoteListFilesRecursively, ReturnsAnEmptyResultWhenNoFilesAreFound) {
  auto temp_dir = std::filesystem::path(GetTestTempDir(test_info_->name()));
  EXPECT_THAT(RemoteListFilesRecursively(temp_dir.string()), IsEmpty());
}

TEST(RemoteFilesListRecursively, ReturnsASingleFileWhenListingAFile) {
  auto temp_dir = std::filesystem::path(GetTestTempDir(test_info_->name()));

  auto file1_path = temp_dir / "file_01";
  ASSERT_TRUE(CreateFile(file1_path.string()));

  const std::vector<std::string> files =
      RemoteListFilesRecursively(temp_dir.string());
  EXPECT_THAT(files, UnorderedElementsAre(file1_path.string()));
}

TEST(RemoteFilesListRecursively, ReturnsAnEmptyVectorWhenPathDoesNotExist) {
  const std::vector<std::string> files =
      RemoteListFilesRecursively("/this/file/path/does/not/exist");
  EXPECT_THAT(files, IsEmpty());
}

}  // namespace
}  // namespace centipede
