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

struct EarlyExit {
  int exit_code = EXIT_SUCCESS;
  bool is_requested = false;
};
std::atomic<EarlyExit> early_exit;

}  // namespace

void RequestEarlyExit(int exit_code) {
  early_exit.store({exit_code, true}, std::memory_order_release);
}

void ClearEarlyExitRequest() {
  early_exit.store({}, std::memory_order_release);
}

bool EarlyExitRequested() {
  return early_exit.load(std::memory_order_acquire).is_requested;
}

int ExitCode() { return early_exit.load(std::memory_order_acquire).exit_code; }

}  // namespace centipede
