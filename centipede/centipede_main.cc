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

#include <vector>

#include "absl/flags/parse.h"
#include "absl/log/globals.h"
#include "absl/log/initialize.h"
#include "./centipede/centipede_default_callbacks.h"
#include "./centipede/centipede_interface.h"
#include "./centipede/config_file.h"
#include "./centipede/environment.h"

int main(int argc, char** argv) {
  const centipede::config::MainRuntimeInit runtime_init =
      [](int argc, char** argv) -> std::vector<std::string> {
    // NB: The invocation order is important here.
    // By default, log everything to stderr. Explicit --stderrthreshold=N on the
    // command line takes precedence.
    absl::SetStderrThreshold(absl::LogSeverityAtLeast::kInfo);
    // Perform the initial command line parsing.
    std::vector<std::string> leftover_argv =
        centipede::config::CastArgv(absl::ParseCommandLine(argc, argv));
    // Initialize the logging subsystem.
    absl::InitializeLog();
    return leftover_argv;
  };

  // Resolve any possible config-related flags in the command line and reparse
  // it if any augmentations had to be made.
  const auto leftover_argv =
      centipede::config::InitCentipede(argc, argv, runtime_init);

  // Reads flags; must happen after ParseCommandLine().
  centipede::Environment env{leftover_argv};
  centipede::DefaultCallbacksFactory<centipede::CentipedeDefaultCallbacks>
      callbacks;
  return CentipedeMain(env, callbacks);
}
