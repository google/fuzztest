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

#include "./common/env_util.h"

#include <cstdlib>
#include <string>

#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"

namespace fuzztest::internal {

absl::Duration GetDurationFromEnv(absl::string_view env_var_name,
                                  absl::Duration default_value) {
  const char* env_val = std::getenv(std::string(env_var_name).c_str());
  if (env_val == nullptr) return default_value;

  absl::Duration duration;
  if (absl::ParseDuration(env_val, &duration)) {
    return duration;
  }

  absl::FPrintF(stderr,
                "[!] Cannot parse env %s=%s as duration. Using default.\n",
                env_var_name, env_val);
  return default_value;
}

}  // namespace fuzztest::internal
