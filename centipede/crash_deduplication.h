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

#include "absl/container/flat_hash_map.h"
#include "absl/time/clock_interface.h"
#include "absl/time/time.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/crash_summary.h"
#include "./centipede/environment.h"
#include "./centipede/stop.h"
#include "./centipede/workdir.h"

namespace fuzztest::internal {

struct CrashDetails {
  std::string input_signature;
  std::string description;
  std::string input_path;
};

// Returns a map of crash signatures to crash details for crashes in the
// workdir. Only one crash per signature is returned, selected arbitrarily.
absl::flat_hash_map<std::string, CrashDetails> GetCrashesFromWorkdir(
    const WorkDir& workdir, size_t total_shards);

// Organizes crashing inputs from `crashing_dir` by attempting to reproduce
// them, and stores new crashes from `new_crashes_by_signature` that are not
// duplicates of existing ones.
//
// The inputs are stored in three directories:
// crashing/: stores crashing inputs in files of the form
//   <bug_id>-<crash.signature>-<input.signature>.
// incubating/: stores inputs that have not crashed recently. Files are of the
// form
//   <input.signature>
// regression/: stores inputs that have not crashed for the specified ttl. Files
// are of the form
//   <input.signature>
//
// Input organization works as follows:
//
// 1) Replay: Replay the inputs in crashing/ and incubating/. Merge with
// new_crashes_by_signature to obtain `active_crashes` - a mapping of
// crash signatures to crashing inputs.
//
// 2) Update crashing/: For each crash in crashing/:
//   > if crash.input reproduces with crash.signature: touch the file
//   > if crash.input crashes with a different signature and crash.signature is
//   in active_crashes: replace the file with
//   <crash.bug>-<crash.signature>-<active_input.signature> where active_input =
//   active_crashes[crash.signature].
//   > if crash.input does not crash at all and crash.signature is in
//   active_crashes: replace the file with
//   <crash.bug>-<crash.signature>-<active_input.signature> where active_input =
//   active_crashes[crash.signature] and move crash.input to
//   incubating/<crash.input.signature>
//
// 3) Record new crashes: Find all crash signatures in active_crashes that do
// not have an entry in crashing/. For each such crash_signature, generate a
// new_bug_id and add crashing/<new_bug_id>-<crash.signature>-<input.signature>
// where input = active_crashes[crash_signature].
//
// 4) Regression: Move expired files in crashing/ and incubating/ to regression/
absl::Status OrganizeCrashingInputs(
    const std::filesystem::path& regression_dir,
    const std::filesystem::path& crashing_dir,
    const std::filesystem::path& incubating_dir, const Environment& env,
    CentipedeCallbacksFactory& callbacks_factory,
    const absl::flat_hash_map<std::string, CrashDetails>&
        new_crashes_by_signature,
    CrashSummary& crash_summary, StopCondition& stop_condition,
    absl::Duration regression_ttl,
    absl::Clock& clock = absl::Clock::GetRealClock());

}  // namespace fuzztest::internal

#endif  // FUZZTEST_CENTIPEDE_CRASH_DEDUPLICATION_H_
