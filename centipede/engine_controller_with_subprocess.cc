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

#include <cstdlib>
#include <cstring>
#include <string>

#include "./centipede/engine_abi.h"
#include "./centipede/engine_controller_abi.h"
#include "./fuzztest/internal/escaping.h"

using fuzztest::internal::ShellEscape;

FuzzTestControllerStatus FuzzTestControllerRun(
    const FuzzTestAdapterManager* manager, const FuzzTestBytesViews* flags) {
  // TODO(xinhaoyuan): Use the FuzzTest controller env var later.
  static auto centipede_binary_path = []() -> const char* {
    const char* env = std::getenv("FUZZTEST_CENTIPEDE_BINARY_PATH");
    if (env == nullptr) return nullptr;
    return strdup(env);
  }();
  if (centipede_binary_path == nullptr) {
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
