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

#include "./centipede/crash_deduplication.h"

#include <cstddef>
#include <filesystem>  // NOLINT
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/crash_summary.h"
#include "./centipede/environment.h"
#include "./centipede/runner_result.h"
#include "./centipede/workdir.h"
#include "./common/crashing_input_filename.h"
#include "./common/defs.h"
#include "./common/hash.h"
#include "./common/logging.h"
#include "./common/remote_file.h"
#include "./common/status_macros.h"

namespace fuzztest::internal {
namespace {

std::string GetInputFileName(std::string_view bug_id,
                             std::string_view crash_signature,
                             std::string_view input_signature) {
  return absl::StrCat(bug_id, "-", crash_signature, "-", input_signature);
}

}  // namespace

absl::flat_hash_map<std::string, CrashDetails> GetCrashesFromWorkdir(
    const WorkDir& workdir, size_t total_shards) {
  absl::flat_hash_map<std::string, CrashDetails> crashes;
  for (size_t shard_idx = 0; shard_idx < total_shards; ++shard_idx) {
    std::vector<std::string> crashing_input_paths =
        // The crash reproducer directory may contain subdirectories with
        // input files that don't individually cause a crash. We ignore those
        // for now and don't list the files recursively.
        ValueOrDie(
            RemoteListFiles(workdir.CrashReproducerDirPaths().Shard(shard_idx),
                            /*recursively=*/false));
    const std::filesystem::path crash_metadata_dir =
        workdir.CrashMetadataDirPaths().Shard(shard_idx);

    for (std::string& crashing_input_path : crashing_input_paths) {
      std::string crashing_input_file_name =
          std::filesystem::path(crashing_input_path).filename();
      const std::string crash_signature_path =
          crash_metadata_dir / absl::StrCat(crashing_input_file_name, ".sig");
      std::string crash_signature;
      const absl::Status status =
          RemoteFileGetContents(crash_signature_path, crash_signature);
      if (!status.ok()) {
        FUZZTEST_LOG(WARNING)
            << "Ignoring crashing input " << crashing_input_file_name
            << " due to failure to read the crash signature: " << status;
        continue;
      }
      if (crashes.contains(crash_signature)) continue;

      const std::string crash_description_path =
          crash_metadata_dir / absl::StrCat(crashing_input_file_name, ".desc");
      std::string crash_description;
      const absl::Status description_status =
          RemoteFileGetContents(crash_description_path, crash_description);
      FUZZTEST_LOG_IF(WARNING, !description_status.ok())
          << "Failed to read crash description for " << crashing_input_file_name
          << ".Status: " << description_status;
      crashes.insert(
          {std::move(crash_signature),
           // Centipede uses the input signature (i.e., the hash of the input)
           // for the crashing input's file name in the workdir.
           CrashDetails{/*input_signature=*/std::move(crashing_input_file_name),
                        /*description=*/std::move(crash_description),
                        /*input_path=*/std::move(crashing_input_path)}});
    }
  }
  return crashes;
}

void OrganizeCrashingInputs(
    const std::filesystem::path& regression_dir,
    const std::filesystem::path& crashing_dir, const Environment& env,
    CentipedeCallbacksFactory& callbacks_factory,
    const absl::flat_hash_map<std::string, CrashDetails>&
        new_crashes_by_signature,
    CrashSummary& crash_summary) {
  FUZZTEST_CHECK_OK(RemoteMkdir(crashing_dir.c_str()));
  FUZZTEST_CHECK_OK(RemoteMkdir(regression_dir.c_str()));

  // The corpus database layout assumes the crash input files are located
  // directly in the crashing directory, so we don't list recursively.
  std::vector<std::string> old_input_files =
      ValueOrDie(RemoteListFiles(crashing_dir.c_str(), /*recursively=*/false));
  size_t crash_input_count = old_input_files.size();
  ScopedCentipedeCallbacks scoped_callbacks(callbacks_factory, env);
  BatchResult batch_result;

  absl::flat_hash_map<std::string, CrashDetails> reproduced_crashes;
  for (const std::string& old_input_file : old_input_files) {
    ByteArray old_input;
    FUZZTEST_CHECK_OK(RemoteFileGetContents(old_input_file, old_input));
    const bool is_reproducible = !scoped_callbacks.callbacks()->Execute(
                                     env.binary, {old_input}, batch_result) &&
                                 batch_result.IsInputFailure();
    auto input_file_components = ParseCrashingInputFilename(old_input_file);
    FUZZTEST_LOG_IF(WARNING, !input_file_components.ok())
        << "Failed to get input file components for " << old_input_file
        << ". Status: " << input_file_components.status();

    if (is_reproducible) {
      if (input_file_components.ok()) {
        // Overwrite the old crash signature with the new one.
        input_file_components->crash_signature =
            batch_result.failure_signature();
      } else {
        // We'll rename the input file to the new format using the input
        // signature as the bug ID.
        const std::string input_signature = Hash(old_input);
        input_file_components = InputFileComponents{
            /*bug_id=*/input_signature,
            /*crash_signature=*/batch_result.failure_signature(),
            /*input_signature=*/input_signature,
        };
      }

      std::string new_input_file_name = GetInputFileName(
          input_file_components->bug_id, input_file_components->crash_signature,
          input_file_components->input_signature);
      std::string new_input_file = crashing_dir / new_input_file_name;
      if (old_input_file == new_input_file) {
        const auto status = RemotePathTouchExistingFile(new_input_file);
        FUZZTEST_LOG_IF(ERROR, !status.ok())
            << "Failed to touch file " << new_input_file
            << ". Status: " << status;
      } else {
        const auto status = RemoteFileRename(old_input_file, new_input_file);
        if (!status.ok()) {
          FUZZTEST_LOG(ERROR)
              << "Failed to rename file " << old_input_file << " to "
              << new_input_file << ". Status: " << status;
          new_input_file_name =
              std::filesystem::path(old_input_file).filename();
          new_input_file = old_input_file;
        }
      }
      // In crash reports we report the full file name as the crash ID. This is
      // what the user can use to replay or export the crash.
      crash_summary.AddCrash({/*id=*/new_input_file_name,
                              /*category=*/batch_result.failure_description(),
                              batch_result.failure_signature(),
                              batch_result.failure_description()});
      reproduced_crashes.try_emplace(
          batch_result.failure_signature(),
          CrashDetails{
              /*input_signature=*/input_file_components->input_signature,
              /*description=*/batch_result.failure_description(),
              /*input_path=*/new_input_file,
          });
      continue;
    }
    FUZZTEST_CHECK(!is_reproducible);

    if (!input_file_components.ok()) {
      // Irreproducible, no bug ID, and no crash signature. Nothing to do with
      // this input but move it to the regression directory.
      const std::string regression_input_file =
          regression_dir / Hash(old_input);
      const auto status =
          RemoteFileRename(old_input_file, regression_input_file);
      if (status.ok()) {
        --crash_input_count;
      } else {
        FUZZTEST_LOG(ERROR)
            << "Failed to rename file " << old_input_file << " to "
            << regression_input_file << ". Status: " << status;
      }
      continue;
    }

    auto crash_it =
        reproduced_crashes.find(input_file_components->crash_signature);
    auto new_crash_it = crash_it == reproduced_crashes.end()
                            ? new_crashes_by_signature.find(
                                  input_file_components->crash_signature)
                            : new_crashes_by_signature.end();
    if (crash_it != reproduced_crashes.end() ||
        new_crash_it == new_crashes_by_signature.end()) {
      const std::string regression_input_file =
          regression_dir / input_file_components->input_signature;
      const auto status = RemoteFileCopy(old_input_file, regression_input_file);
      FUZZTEST_LOG_IF(ERROR, !status.ok())
          << "Failed to copy file " << old_input_file << " to "
          << regression_input_file << ". Status: " << status;
      continue;
    }
    crash_it = reproduced_crashes.insert(*new_crash_it).first;

    const std::string new_input_file_name = GetInputFileName(
        input_file_components->bug_id, input_file_components->crash_signature,
        crash_it->second.input_signature);
    const std::string new_input_file = crashing_dir / new_input_file_name;
    absl::Status replace_status;
    if (new_input_file == old_input_file) {
      // For some reason, the old input couldn't reproduce the crash during
      // reproduction, but it was re-discovered during fuzzing, so it is
      // flaky. We keep the input and don't store it as a regression.
      replace_status = RemotePathTouchExistingFile(new_input_file);
      FUZZTEST_LOG_IF(ERROR, !replace_status.ok())
          << "Failed to touch file " << new_input_file
          << ". Status: " << replace_status;
    } else {
      const std::string regression_input_file =
          regression_dir / input_file_components->input_signature;
      replace_status = RemoteFileRename(old_input_file, regression_input_file);
      if (replace_status.ok()) {
        --crash_input_count;
        replace_status =
            RemoteFileCopy(crash_it->second.input_path, new_input_file);
        if (replace_status.ok()) {
          ++crash_input_count;
        } else {
          FUZZTEST_LOG(ERROR)
              << "Failed to copy file " << crash_it->second.input_path << " to "
              << new_input_file << ". Status: " << replace_status;
        }
      } else {
        FUZZTEST_LOG(ERROR)
            << "Failed to rename file " << old_input_file << " to "
            << regression_input_file << ". Status: " << replace_status;
      }
    }
    if (replace_status.ok()) {
      crash_summary.AddCrash({/*id=*/new_input_file_name,
                              /*category=*/crash_it->second.description,
                              input_file_components->crash_signature,
                              crash_it->second.description});
    } else {
      reproduced_crashes.erase(crash_it);
    }
  }

  static constexpr int kMaxCrashInputCount = 10;
  for (auto& [crash_signature, details] : new_crashes_by_signature) {
    if (reproduced_crashes.contains(crash_signature)) continue;
    if (crash_input_count >= kMaxCrashInputCount) {
      FUZZTEST_LOG(WARNING)
          << "Reached the maximum number of crash inputs: "
          << kMaxCrashInputCount << ". Not storing any new crashes.";
      break;
    }
    const std::string bug_id = Hash(
        absl::StrCat(absl::FormatTime(absl::Now()), details.input_signature));
    const std::string new_input_file_name =
        GetInputFileName(bug_id, crash_signature, details.input_signature);
    const std::string new_input_file = crashing_dir / new_input_file_name;
    const auto status = RemoteFileCopy(details.input_path, new_input_file);
    if (!status.ok()) {
      FUZZTEST_LOG(ERROR) << "Failed to copy file " << details.input_path
                          << " to " << new_input_file << ". Status: " << status;
      continue;
    }
    crash_summary.AddCrash({/*id=*/new_input_file_name,
                            /*category=*/details.description, crash_signature,
                            details.description});
    reproduced_crashes.insert({std::move(crash_signature), std::move(details)});
    ++crash_input_count;
  }
}

}  // namespace fuzztest::internal
