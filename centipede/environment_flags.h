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

#ifndef THIRD_PARTY_CENTIPEDE_ENVIRONMENT_FLAGS_H_
#define THIRD_PARTY_CENTIPEDE_ENVIRONMENT_FLAGS_H_

#include <string>
#include <vector>

#include "./centipede/environment.h"
#include "./fuzztest/internal/configuration.h"

namespace centipede {

// Create an Environment object from command line flags defined in
// environment_flags.cc.
Environment CreateEnvironmentFromFlags(
    const std::vector<std::string> &argv = {});

// Returns `env` adjusted for the `config` obtained from the target binary.
// Check-fails if the values in `config` are inconsistent with the corresponding
// values passed by flags.
Environment AdjustEnvironmentForTargetConfig(
    Environment env, const fuzztest::internal::Configuration &config);

}  // namespace centipede

#endif  // THIRD_PARTY_CENTIPEDE_ENVIRONMENT_FLAGS_H_
