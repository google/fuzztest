// Copyright 2025 The Centipede Authors.
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

#ifndef FUZZTEST_CENTIPEDE_CRASH_DEDUPLICATION_H_
#define FUZZTEST_CENTIPEDE_CRASH_DEDUPLICATION_H_

#include <cstddef>
#include <filesystem>  // NOLINT
#include <string>
#include <string_view>

#include "absl/container/flat_hash_map.h"
#include "absl/status/statusor.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/crash_summary.h"
#include "./centipede/environment.h"
#include "./centipede/workdir.h"

namespace fuzztest::internal {

struct CrashDetails {
  std::string input_signature;
  std::string description;
  std::string file_path;
};

// Returns a map of crash signatures to crash details for crashes in the
// workdir. Only one crash per signature is returned, selected arbitrarily.
absl::flat_hash_map<std::string, CrashDetails> GetCrashesFromWorkdir(
    const WorkDir& workdir, size_t total_shards);

struct InputFileComponents {
  // The identifier that is used to keep track of the crash over time even if
  // the crash signature or the crashing input changes.
  std::string bug_id;
  // The hash of the crash metadata used to deduplicate crashes.
  std::string crash_signature;
  // The hash of the input.
  std::string input_signature;
};

// Returns the components of an input file extracted from the file name.
// The file name is expected to be in the format
// `<bug_id>-<crash_signature>-<input_signature>` or `<input_signature>` for
// backwards compatibility.
absl::StatusOr<InputFileComponents> GetInputFileComponents(
    std::string_view input_file_path);

// Organizes crashing inputs from `crashing_dir` and `regression_dir` by
// attempting to reproduce them, and stores new crashes from `new_crashes` that
// are not duplicates of existing ones.
//
// 1. Inputs from `crashing_dir` and `regression_dir` are re-executed:
//   - If an input is reproducible and causes an ordinary crash (i.e., not a
//     setup failure or other special cases):
//     - It is kept in `crashing_dir`.
//     - If its crash signature has changed, it is renamed to reflect the new
//       signature: `<bug_id>-<new_crash_signature>-<input_signature>`.
//   - If an input is not reproducible or doesn't cause an ordinary crash:
//     - If its crash signature is reproduced by another input (either an old
//       reproducible input or one of `new_crashes`), its `bug_id` is reused to
//       ensure crash continuity: a new file
//       `<bug_id>-<crash_signature>-<other_input_signature>` is created in
//       `crashing_dir` with the content of the other reproducible input, and
//       the irreproducible input file is deleted.
//     - Otherwise, if its crash signature is not reproduced by any other
//       input, it is moved to `regression_dir`.
//
// 2. New crashes from `new_crashes` are stored:
//   - If a new crash has a signature that was not observed among reproducible
//     inputs from step 1, it is stored in `crashing_dir` with a newly
//     generated `bug_id`: `<new_bug_id>-<crash_signature>-<input_signature>`.
//
// 3. All crashes that are in `crashing_dir` at the end of this process are
//    reported to `crash_summary`.
void OrganizeOldInputsAndStoreNewCrashes(
    const std::filesystem::path& regression_dir,
    const std::filesystem::path& crashing_dir, const Environment& env,
    CentipedeCallbacksFactory& callbacks_factory,
    const absl::flat_hash_map<std::string, CrashDetails>& new_crashes,
    CrashSummary& crash_summary);

}  // namespace fuzztest::internal

#endif  // FUZZTEST_CENTIPEDE_CRASH_DEDUPLICATION_H_
