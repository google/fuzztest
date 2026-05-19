// Copyright 2026 The Centipede Authors.
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

#ifndef FUZZTEST_COMMON_ENV_UTIL_H_
#define FUZZTEST_COMMON_ENV_UTIL_H_

#include "absl/strings/string_view.h"
#include "absl/time/time.h"

namespace fuzztest::internal {

// Returns the duration parsed from the environment variable `env_var_name`.
// If the variable is unset or cannot be parsed, returns `default_value`.
absl::Duration GetDurationFromEnv(absl::string_view env_var_name,
                                  absl::Duration default_value);

}  // namespace fuzztest::internal

#endif  // FUZZTEST_COMMON_ENV_UTIL_H_
