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

#include <unistd.h>

#include <csignal>
#include <cstdlib>

#include "absl/base/nullability.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/centipede_default_callbacks.h"
#include "./centipede/centipede_interface.h"
#include "./centipede/config_file.h"
#include "./centipede/environment_flags.h"
#include "./centipede/stop.h"

namespace {
fuzztest::internal::StopCondition global_stop_condition;

void SetSignalHandlers() {
  struct sigaction sigact = {};
  sigact.sa_flags = SA_ONSTACK;
  sigact.sa_handler = [](int received_signum) {
    if (received_signum != SIGINT) return;
    const char msg[] = "\n[!] Ctrl-C pressed: winding down\n";
    [[maybe_unused]] auto write_res =
        write(STDERR_FILENO, msg, sizeof(msg) - 1);
    global_stop_condition.RequestEarlyStop(EXIT_FAILURE);
  };
  sigaction(SIGINT, &sigact, nullptr);
}
}  // namespace

int main(int argc, char** absl_nonnull argv) {
  const auto runtime_state = fuzztest::internal::InitCentipede(argc, argv);
  const auto env = fuzztest::internal::CreateEnvironmentFromFlags(
      runtime_state->leftover_argv());
  fuzztest::internal::DefaultCallbacksFactory<
      fuzztest::internal::CentipedeDefaultCallbacks>
      callbacks;
  SetSignalHandlers();
  return CentipedeMain(env, callbacks, &global_stop_condition);
}
