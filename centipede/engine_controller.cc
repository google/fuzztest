// Copyright 2026 The FuzzTest Authors.
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

#include <cstddef>
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <optional>
#include <string>
#include <utility>

#include "absl/flags/marshalling.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "absl/strings/strip.h"
#include "absl/time/time.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/centipede_default_callbacks.h"
#include "./centipede/centipede_interface.h"
#include "./centipede/command.h"
#include "./centipede/engine_abi.h"
#include "./centipede/engine_controller_abi.h"
#include "./centipede/environment.h"
#include "./centipede/in_process_centipede_callbacks.h"
#include "./common/logging.h"
#include "./fuzztest/internal/escaping.h"

namespace fuzztest::internal {
namespace {

absl::string_view ToStringView(FuzzTestBytesView view) {
  if (view.size == 0) return {};
  return {reinterpret_cast<const char*>(view.data), view.size};
}

std::optional<Environment> CreateEnvironmentFromControllerFlags(
    const FuzzTestBytesViews* flags) {
  if (flags != nullptr && flags->count > 0 && flags->views == nullptr) {
    FUZZTEST_LOG(ERROR) << "Flags views pointer is null with non-zero count";
    return std::nullopt;
  }

  Environment env;
  const size_t flag_count = flags == nullptr ? 0 : flags->count;
  for (size_t i = 0; i < flag_count; ++i) {
    const absl::string_view arg = ToStringView(flags->views[i]);
    absl::string_view stripped = arg;
    if (!absl::ConsumePrefix(&stripped, "--")) {
      FUZZTEST_LOG(ERROR) << "Expected flag in --flag=value format, got: "
                          << arg;
      return std::nullopt;
    }

    const size_t eq_pos = stripped.find('=');
    if (eq_pos == absl::string_view::npos || eq_pos == 0) {
      FUZZTEST_LOG(ERROR) << "Expected flag in --flag=value format, got: "
                          << arg;
      return std::nullopt;
    }
    const absl::string_view flag_name = stripped.substr(0, eq_pos);
    const absl::string_view value_str = stripped.substr(eq_pos + 1);

    bool matched = false;
    std::string error;
#define CENTIPEDE_FLAG(_TYPE, NAME, _DEFAULT, _DESC)                           \
  if (!matched && flag_name == #NAME) {                                        \
    if (!absl::ParseFlag(value_str, &env.NAME, &error)) {                      \
      FUZZTEST_LOG(ERROR) << "Failed to parse value '" << value_str            \
                          << "' for flag --" << flag_name                      \
                          << (error.empty() ? "" : absl::StrCat(": ", error)); \
      return std::nullopt;                                                     \
    }                                                                          \
    matched = true;                                                            \
  }
#include "./centipede/centipede_flags.inc"
#undef CENTIPEDE_FLAG

    if (!matched) {
      FUZZTEST_LOG(ERROR) << "Unknown Centipede flag: " << arg;
      return std::nullopt;
    }
  }

  if (env.j != 0) {
    env.total_shards = env.j;
    env.num_threads = env.j;
    env.my_shard_index = 0;
  }
  if (env.total_shards < 1 || env.batch_size < 1 || env.num_threads < 1 ||
      env.num_threads > env.total_shards ||
      env.my_shard_index > env.total_shards - env.num_threads) {
    FUZZTEST_LOG(ERROR) << "Invalid shard or batch configuration: "
                        << VV(env.total_shards) << VV(env.batch_size)
                        << VV(env.num_threads) << VV(env.my_shard_index);
    return std::nullopt;
  }

  if (env.coverage_binary.empty()) {
    env.coverage_binary = *absl::StrSplit(env.binary, ' ').begin();
  }
  env.binary_name =
      std::filesystem::path(env.coverage_binary).filename().string();
  env.UpdateBinaryHashIfEmpty();

  env.UpdateTimeoutPerBatchIfEqualTo(Environment::Default().timeout_per_batch);

  if (!env.clang_coverage_binary.empty()) {
    env.extra_binaries.push_back(env.clang_coverage_binary);
  }

  if (absl::StrContains(env.binary, "@@")) {
    FUZZTEST_LOG(INFO)
        << "@@ detected; running in standalone mode with batch_size=1";
    env.has_input_wildcards = true;
    env.batch_size = 1;
  }

  env.ReadKnobsFileIfSpecified();
  return env;
}

FuzzTestControllerStatus RunControllerBinary(absl::string_view binary_path,
                                             const FuzzTestBytesViews* flags) {
  if (binary_path.empty()) {
    FUZZTEST_LOG(ERROR) << "FUZZTEST_CENTIPEDE_BINARY_PATH is empty";
    return kFuzzTestControllerFailure;
  }
  if (flags != nullptr && flags->count > 0 && flags->views == nullptr) {
    FUZZTEST_LOG(ERROR) << "Flags views pointer is null with non-zero count";
    return kFuzzTestControllerFailure;
  }

  Command::Options cmd_options;
  const size_t flag_count = flags == nullptr ? 0 : flags->count;
  cmd_options.args.reserve(flag_count);
  for (size_t i = 0; i < flag_count; ++i) {
    // TODO(b/381910257): No need to escape here once the bug is fixed.
    cmd_options.args.push_back(ShellEscape(ToStringView(flags->views[i])));
  }

  Command cmd{binary_path, std::move(cmd_options)};
  return cmd.Execute() == EXIT_SUCCESS ? kFuzzTestControllerSuccess
                                       : kFuzzTestControllerFailure;
}

}  // namespace
}  // namespace fuzztest::internal

extern "C" FuzzTestControllerStatus FuzzTestControllerRun(
    const FuzzTestAdapterManager* manager, const FuzzTestBytesViews* flags) {
  if (const char* centipede_binary_path =
          std::getenv("FUZZTEST_CENTIPEDE_BINARY_PATH");
      centipede_binary_path != nullptr) {
    return fuzztest::internal::RunControllerBinary(centipede_binary_path,
                                                   flags);
  }

  const std::optional<fuzztest::internal::Environment> env =
      fuzztest::internal::CreateEnvironmentFromControllerFlags(flags);
  if (!env.has_value()) {
    return kFuzzTestControllerFailure;
  }

  int ret = EXIT_FAILURE;
  if (env->binary.empty() && manager != nullptr) {
    fuzztest::internal::InProcessCentipedeCallbacksFactory factory(manager);
    ret = fuzztest::internal::CentipedeMain(*env, factory);
  } else {
    fuzztest::internal::DefaultCallbacksFactory<
        fuzztest::internal::CentipedeDefaultCallbacks>
        factory;
    ret = fuzztest::internal::CentipedeMain(*env, factory);
  }
  return ret == EXIT_SUCCESS ? kFuzzTestControllerSuccess
                             : kFuzzTestControllerFailure;
}
