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

#include "./centipede/flag_utils.h"

#include <cstdlib>

#include "absl/base/nullability.h"

namespace fuzztest::internal {

FlagHelper flag_helper __attribute__((init_priority(198)));

extern "C" __attribute__((weak)) const char *absl_nullable
CentipedeGetRunnerFlags() {
  if (const char *runner_flags_env = getenv("CENTIPEDE_RUNNER_FLAGS"))
    return strdup(runner_flags_env);
  return nullptr;
}

}  // namespace fuzztest::internal
