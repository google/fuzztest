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

#ifndef FUZZTEST_CENTIPEDE_FLAG_UTIL_H_
#define FUZZTEST_CENTIPEDE_FLAG_UTIL_H_

#include <cstdint>

#include "absl/base/nullability.h"

extern "C" const char *absl_nullable CentipedeGetRunnerFlags();

// Returns true iff `flag` is present.
// Typical usage: pass ":some_flag:", i.e. the flag name surrounded with ':'.
// TODO(ussuri): Refactor `char *` into a `string_view`.
bool HasFlag(const char *absl_nonnull flag);

// If a flag=value pair is present, returns value,
// otherwise returns `default_value`.
// Typical usage: pass ":some_flag=".
// TODO(ussuri): Refactor `char *` into a `string_view`.
uint64_t HasIntFlag(const char *absl_nonnull flag, uint64_t default_value);

#endif  // FUZZTEST_CENTIPEDE_FLAG_UTIL_H_
