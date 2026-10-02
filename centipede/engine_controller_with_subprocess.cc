// Copyright 2026 The FuzzTest Authors.
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

#include <sys/wait.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>  // NOLINT
#include <string>
#include <system_error>  // NOLINT

#include "./centipede/engine_abi.h"
#include "./centipede/engine_controller_abi.h"
#include "./fuzztest/internal/escaping.h"

namespace {

using fuzztest::internal::ShellEscape;

std::string GetBundledCentipedeBinaryPath() {
  constexpr const char* kBundledCentipedePathSuffix =
  "centipede/centipede_uninstrumented";
  const char* test_workspace = std::getenv("TEST_WORKSPACE");
  if (test_workspace == nullptr) {
    test_workspace = "_main";
  }
  std::string runfiles_dir;
  if (const char* test_srcdir = std::getenv("TEST_SRCDIR");
      test_srcdir != nullptr) {
    runfiles_dir = test_srcdir;
  }
  std::error_code ec;
  if (!runfiles_dir.empty()) {
    const auto path = std::filesystem::path{runfiles_dir} / test_workspace /
                      kBundledCentipedePathSuffix;
    if (std::filesystem::exists(path, ec)) {
      return path.string();
    }
  }
  return "";
}

}  // namespace

FuzzTestControllerStatus FuzzTestControllerRun(
    const FuzzTestAdapterManager* manager, const FuzzTestBytesViews* flags) {
  static auto centipede_binary_path = []() -> const char* {
    // TODO(xinhaoyuan): Use the FuzzTest controller env var later.
    if (const char* env = std::getenv("FUZZTEST_CENTIPEDE_BINARY_PATH");
        env != nullptr) {
      return strdup(env);
    }
    const std::string bundled_path = GetBundledCentipedeBinaryPath();
    if (!bundled_path.empty()) {
      return strdup(bundled_path.c_str());
    }
    return nullptr;
  }();
  if (centipede_binary_path == nullptr) {
    fprintf(stderr,
            "Failed to locate the controller binary - please specify the env "
            "var `FUZZTEST_CENTIPEDE_BINARY_PATH`\n");
    return kFuzzTestControllerFailure;
  }
  std::string command;
  command.append(ShellEscape(centipede_binary_path));
  for (size_t flag_index = 0; flag_index < flags->count; ++flag_index) {
    const FuzzTestBytesView flag = flags->views[flag_index];
    command.append(" ");
    command.append(
        ShellEscape({reinterpret_cast<const char*>(flag.data), flag.size}));
  }
  int ret = system(command.c_str());
  if (ret == -1) return kFuzzTestControllerFailure;
  return WIFEXITED(ret) && WEXITSTATUS(ret) == EXIT_SUCCESS
             ? kFuzzTestControllerSuccess
             : kFuzzTestControllerFailure;
}
