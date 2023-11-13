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

#include "./centipede/early_exit.h"

#include <atomic>
#include <cstdlib>

namespace centipede {
namespace {
std::atomic<int> requested_exit_code = EXIT_SUCCESS;
std::atomic<bool> early_exit_requested = false;
}  // namespace

void RequestEarlyExit(int exit_code) {
  requested_exit_code = exit_code;
  early_exit_requested = true;
}

bool EarlyExitRequested() { return early_exit_requested; }

int ExitCode() { return requested_exit_code; }
}  // namespace centipede
