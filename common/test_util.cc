// Copyright 2022 The Centipede Authors.
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

#include <cstdlib>
#include <filesystem>  // NOLINT
#include <string>
#include <string_view>
#include <system_error>  // NOLINT

#if !defined(_WIN32)
#include <unistd.h>
#else
#define WIN32_LEAN_AND_MEAN
#define NOGDI
#include <process.h>
#include <windows.h>
#endif

#include "gtest/gtest.h"
#include "absl/strings/str_cat.h"
#include "./common/logging.h"

#if defined(_WIN32)
#define setenv(n, v, _r) _putenv_s(n, v)
#endif

namespace fuzztest::internal {

std::filesystem::path GetTestTempDir(std::string_view subdir) {
  const std::filesystem::path test_tempdir = ::testing::TempDir();
  FUZZTEST_CHECK(!test_tempdir.empty())
      << "testing::TempDir() is expected to always return non-empty path";
  const auto dir = test_tempdir / subdir;
  if (!std::filesystem::exists(dir)) {
    std::error_code error;
    std::filesystem::create_directories(dir, error);
    FUZZTEST_CHECK(!error) << "Failed to create dir: " VV(dir)
                           << error.message();
  }
  return std::filesystem::absolute(dir);
}

std::string GetTempFilePath(std::string_view subdir, size_t i) {
  return (GetTestTempDir(subdir) / absl::StrCat("tmp.",
#if defined(_WIN32)
                                                GetCurrentProcessId(),
#else
                                                getpid(),
#endif
                                                ".", i))
      .string();
}

std::filesystem::path GetTestRunfilesDir() {
  const auto test_srcdir = ::testing::SrcDir();
  FUZZTEST_CHECK(!test_srcdir.empty())
      << "testing::SrcDir() is expected to always return non-empty path";
  const char* test_workspace = std::getenv("TEST_WORKSPACE");
  FUZZTEST_CHECK(test_workspace != nullptr)
      << "TEST_WORKSPACE envvar is expected to be set by build system";
  auto path = std::filesystem::path{test_srcdir}.append(test_workspace);
  FUZZTEST_CHECK(std::filesystem::exists(path))  //
      << "No such dir: " << VV(path) << VV(test_srcdir) << VV(test_workspace);
  return path;
}

std::filesystem::path GetDataDependencyFilepath(std::string_view rel_path) {
  const auto runfiles_dir = GetTestRunfilesDir();
  auto path = runfiles_dir;
  path.append(rel_path);
  std::error_code ec;
  if (std::filesystem::exists(path, ec)) return path;
#if defined(_WIN32)
  auto win_path = path;
  win_path += ".exe";
  if (std::filesystem::exists(win_path, ec)) return win_path;
#endif
  FUZZTEST_CHECK(std::filesystem::exists(path))  //
      << "No such path: " << VV(path) << VV(runfiles_dir) << VV(rel_path);
  return path;
}

std::string GetLLVMSymbolizerPath() {
  FUZZTEST_CHECK_EQ(system("which llvm-symbolizer"), EXIT_SUCCESS)
      << "llvm-symbolizer has to be installed and findable via PATH";
  return "llvm-symbolizer";
}

std::string GetObjDumpPath() {
  FUZZTEST_CHECK_EQ(system("which objdump"), EXIT_SUCCESS)
      << "objdump has to be installed and findable via PATH";
  return "objdump";
}

void PrependDirToPathEnvvar(std::string_view dir) {
  const std::string new_path_envvar = absl::StrCat(dir, ":", getenv("PATH"));
  setenv("PATH", new_path_envvar.c_str(), /*replace*/ 1);
  FUZZTEST_LOG(INFO) << "New PATH: " << new_path_envvar;
}

}  // namespace fuzztest::internal
