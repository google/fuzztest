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

#include "./centipede/flag_util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <cstdint>

#include "absl/base/nullability.h"

extern "C" __attribute__((weak)) const char *absl_nullable
CentipedeGetRunnerFlags() {
  if (const char *runner_flags_env = getenv("CENTIPEDE_RUNNER_FLAGS"))
    return strdup(runner_flags_env);
  return nullptr;
}

static const char *centipede_runner_flags = CentipedeGetRunnerFlags();

bool HasFlag(const char *absl_nonnull flag) {
  fprintf(stderr, "HasFlag %s\n", flag);
  fprintf(stderr, "centipede_runner_flags %s\n", centipede_runner_flags);
  if (!centipede_runner_flags) return false;
  return strstr(centipede_runner_flags, flag) != nullptr;
}

uint64_t HasIntFlag(const char *absl_nonnull flag, uint64_t default_value) {
  if (!centipede_runner_flags) return default_value;
  const char *beg = strstr(centipede_runner_flags, flag);
  if (!beg) return default_value;
  return atoll(beg + strlen(flag));  // NOLINT: can't use strto64, etc.
}
