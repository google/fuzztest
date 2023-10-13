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

#include "./fuzztest/internal/io.h"

#include <sys/stat.h>

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <optional>
#include <string>

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "./fuzztest/fuzztest.h"

namespace fuzztest::internal {
namespace {

using ::testing::Eq;
using ::testing::FieldsAre;
using ::testing::IsEmpty;
using ::testing::Optional;
using ::testing::SizeIs;
using ::testing::UnorderedElementsAre;

std::string TmpFile(const std::string& name) {
  std::string filename = absl::StrCat(testing::TempDir(), "/", name, "XXXXXX");
  return mktemp(filename.data());
}

std::string TmpDir(const std::string& name) {
  std::string filename = absl::StrCat(testing::TempDir(), "/", name, "XXXXXX");
  return mkdtemp(filename.data());
}

// These use a different implementation of read/write.
// Otherwise we are testing the functions with themselves.
std::string TestRead(const std::string& filename) {
  FILE* f = fopen(filename.c_str(), "r");
  char buf[1024]{};
  size_t s = fread(buf, 1, sizeof(buf), f);
  fclose(f);
  return std::string(buf, s);
}

void TestWrite(const std::string& filename, const std::string& contents) {
  FILE* f = fopen(filename.c_str(), "w");
  ASSERT_TRUE(f) << strerror(errno);
  EXPECT_EQ(fwrite(contents.data(), contents.size(), 1, f), 1)
      << strerror(errno);
  EXPECT_EQ(0, fclose(f)) << strerror(errno);
}

TEST(IOTest, WriteFileWorksWhenDirectoryExists) {
  const std::string tmp_name = TmpFile("write_test");
  EXPECT_TRUE(WriteFile(tmp_name, "Payload1"));
  EXPECT_EQ(TestRead(tmp_name), "Payload1");
  std::filesystem::remove(tmp_name);
}

TEST(IOTest, WriteFileWorksWhenDirectoryDoesNotExist) {
  const std::string tmp_dir = TmpDir("write_test_dir");
  const std::string tmp_name = absl::StrCat(tmp_dir, "/doesnt_exist/file");
  EXPECT_TRUE(WriteFile(tmp_name, "Payload1"));
  EXPECT_EQ(TestRead(tmp_name), "Payload1");
  std::filesystem::remove_all(tmp_dir);
}

TEST(IOTest, WriteDataToDirReturnsWrittenFilePath) {
  const std::string tmp_dir = TmpDir("write_test_dir");
  const std::string path = WriteDataToDir("data", tmp_dir);
  EXPECT_THAT(ReadFile(path), Optional(Eq("data")));
  std::filesystem::remove_all(tmp_dir);
}

TEST(IOTest, WriteDataToDirWritesToSameFileOnSameData) {
  const std::string tmp_dir = TmpDir("write_test_dir");
  const std::string path = WriteDataToDir("data", tmp_dir);
  EXPECT_THAT(WriteDataToDir("data", tmp_dir), Eq(path));
  EXPECT_THAT(ReadFile(path), Optional(Eq("data")));
  std::filesystem::remove_all(tmp_dir);
}

TEST(IOTest, ReadFileReturnsNulloptWhenMissing) {
  EXPECT_THAT(ReadFile("/doesnt_exist/file"), Eq(std::nullopt));
  EXPECT_THAT(ReadFileOrDirectory("/doesnt_exist/file"),
              UnorderedElementsAre());
}

TEST(IOTest, ReadFileWorksWhenFileExists) {
  const std::string tmp_name = TmpFile("read_test");
  TestWrite(tmp_name, "Payload2");
  EXPECT_THAT(ReadFile(tmp_name), Optional(Eq("Payload2")));
  EXPECT_THAT(ReadFileOrDirectory(tmp_name),
              UnorderedElementsAre(FieldsAre(tmp_name, "Payload2")));
  std::filesystem::remove(tmp_name);
}

TEST(IOTest, ReadFileOrDirectoryWorks) {
  const std::string tmp_dir = TmpDir("write_test_dir");
  EXPECT_THAT(ReadFileOrDirectory(tmp_dir), UnorderedElementsAre());
  const std::string tmp_file_1 = absl::StrCat(tmp_dir, "/file1");
  TestWrite(tmp_file_1, "Payload3.1");
  EXPECT_THAT(ReadFileOrDirectory(tmp_dir),
              UnorderedElementsAre(FieldsAre(tmp_file_1, "Payload3.1")));
  const std::string tmp_file_2 = absl::StrCat(tmp_dir, "/file2");
  TestWrite(tmp_file_2, "Payload3.2");
  EXPECT_THAT(ReadFileOrDirectory(tmp_dir),
              UnorderedElementsAre(FieldsAre(tmp_file_1, "Payload3.1"),
                                   FieldsAre(tmp_file_2, "Payload3.2")));
  std::filesystem::remove_all(tmp_dir);
}

TEST(IOTest, ReadFileOrDirectoryWorksRecursively) {
  const std::string tmp_dir = TmpDir("test_dir");
  const std::string tmp_sub_dir = absl::StrCat(tmp_dir, "/subdir");
  mkdir(tmp_sub_dir.c_str(), 0700);
  const std::string tmp_file_1 = absl::StrCat(tmp_dir, "/file1");
  TestWrite(tmp_file_1, "Payload5.1");
  const std::string tmp_file_2 = absl::StrCat(tmp_sub_dir, "/file2");
  TestWrite(tmp_file_2, "Payload5.2");
  EXPECT_THAT(ReadFileOrDirectory(tmp_dir),
              UnorderedElementsAre(FieldsAre(tmp_file_1, "Payload5.1"),
                                   FieldsAre(tmp_file_2, "Payload5.2")));
  std::filesystem::remove_all(tmp_dir);
}

TEST(IOTest, ReadFilesFromDirectoryWorks) {
  const std::string tmp_dir = TmpDir("write_test_dir");
  EXPECT_THAT(ReadFilesFromDirectory(tmp_dir), UnorderedElementsAre());
  EXPECT_THAT(ReadFilesFromDirectory(tmp_dir), SizeIs(0));
  const std::string tmp_file_1 = absl::StrCat(tmp_dir, "/file1");
  TestWrite(tmp_file_1, "Payload4.1");
  EXPECT_THAT(ReadFilesFromDirectory(tmp_dir),
              UnorderedElementsAre(FieldsAre("Payload4.1")));
  EXPECT_THAT(ReadFilesFromDirectory(tmp_dir), SizeIs(1));
  const std::string tmp_file_2 = absl::StrCat(tmp_dir, "/file2");
  TestWrite(tmp_file_2, "Payload4.2");
  EXPECT_THAT(
      ReadFilesFromDirectory(tmp_dir),
      UnorderedElementsAre(FieldsAre("Payload4.1"), FieldsAre("Payload4.2")));
  EXPECT_THAT(ReadFilesFromDirectory(tmp_dir), SizeIs(2));
  std::filesystem::remove_all(tmp_dir);
}

TEST(IOTest, ReadFilesFromDirectoryReturnsEmptyVectorWhenNoFilesInDir) {
  const std::string tmp_dir = TmpDir("empty_dir");
  EXPECT_THAT(ReadFilesFromDirectory(tmp_dir), UnorderedElementsAre());
  EXPECT_THAT(ReadFileOrDirectory(tmp_dir), SizeIs(0));
  std::filesystem::remove_all(tmp_dir);
}

TEST(IOTest, ReadFilesFromDirectoryReturnsEmptyVectorWhenMissing) {
  EXPECT_THAT(ReadFilesFromDirectory("/doesnt_exist/"), UnorderedElementsAre());
  EXPECT_THAT(ReadFileOrDirectory("/doesnt_exist/"), SizeIs(0));
}

TEST(IOTest, ListDirectoryReturnsPathsInDirectory) {
  const std::string tmp_dir = TmpDir("test_dir");
  const std::string tmp_file_1 = absl::StrCat(tmp_dir, "/file1");
  TestWrite(tmp_file_1, /*contents=*/"File1");
  const std::string tmp_file_2 = absl::StrCat(tmp_dir, "/file2");
  TestWrite(tmp_file_2, /*contents=*/"File2");
  EXPECT_THAT(ListDirectory(tmp_dir),
              UnorderedElementsAre(tmp_file_1, tmp_file_2));
  std::filesystem::remove_all(tmp_dir);
}

TEST(IOTest, ListDirectoryReturnsEmptyVectorWhenDirectoryIsEmpty) {
  const std::string tmp_dir = TmpDir("empty_dir");
  EXPECT_THAT(ListDirectory(tmp_dir), IsEmpty());
  std::filesystem::remove_all(tmp_dir);
}

TEST(IOTest, ListDirectoryReturnsEmptyVectorWhenDirectoryDoesNotExist) {
  EXPECT_THAT(ListDirectory("/doesnt_exist/"), IsEmpty());
}

}  // namespace
}  // namespace fuzztest::internal
