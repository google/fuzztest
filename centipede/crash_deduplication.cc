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
#include <iterator>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/crash_summary.h"
#include "./centipede/environment.h"
#include "./centipede/runner_result.h"
#include "./centipede/workdir.h"
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

absl::StatusOr<InputFileComponents> GetInputFileComponents(
    std::string_view input_file_path) {
  const std::string file_name =
      std::filesystem::path(std::string(input_file_path)).filename();
  std::vector<std::string> parts = absl::StrSplit(file_name, '-');
  if (parts.size() == 1) {
    // Old format where the input file name is both the bug ID and the input
    // signature.
    return InputFileComponents{
        /*bug_id=*/parts[0],
        /*crash_signature=*/"",
        /*input_signature=*/parts[0],
    };
  }
  if (parts.size() < 3) {
    return absl::InvalidArgumentError(
        absl::StrCat("Input file name not in the format of "
                     "<bug_id>-<crash_signature>-<input_signature>: ",
                     file_name));
  }
  return InputFileComponents{
      /*bug_id=*/absl::StrJoin(parts.begin(), parts.end() - 2, "-"),
      /*crash_signature=*/std::move(parts[parts.size() - 2]),
      /*input_signature=*/std::move(parts[parts.size() - 1]),
  };
}

void OrganizeOldInputsAndStoreNewCrashes(
    const std::filesystem::path& regression_dir,
    const std::filesystem::path& crashing_dir, const Environment& env,
    CentipedeCallbacksFactory& callbacks_factory,
    const absl::flat_hash_map<std::string, CrashDetails>& new_crashes,
    CrashSummary& crash_summary) {
  // The corpus database layout assumes the crash input files are located
  // directly in the crashing/regression subdirectories, so we don't list
  // recursively.
  std::vector<std::string> old_input_files =
      ValueOrDie(RemoteListFiles(crashing_dir.c_str(), /*recursively=*/false));
  std::vector<std::string> regression_input_files = ValueOrDie(
      RemoteListFiles(regression_dir.c_str(), /*recursively=*/false));
  int crash_and_regression_input_count =
      old_input_files.size() + regression_input_files.size();
  old_input_files.reserve(crash_and_regression_input_count);
  old_input_files.insert(
      old_input_files.end(),
      std::make_move_iterator(regression_input_files.begin()),
      std::make_move_iterator(regression_input_files.end()));
  ScopedCentipedeCallbacks scoped_callbacks(callbacks_factory, env);
  BatchResult batch_result;

  std::vector<std::string> irreproducible_input_files;
  absl::flat_hash_map<std::string, CrashDetails> reproduced_crashes;
  for (std::string& old_input_file : old_input_files) {
    ByteArray old_input;
    FUZZTEST_CHECK_OK(RemoteFileGetContents(old_input_file, old_input));
    const bool is_reproducible = !scoped_callbacks.callbacks()->Execute(
        env.binary, {old_input}, batch_result);
    if (!(is_reproducible && batch_result.IsInputFailure())) {
      irreproducible_input_files.push_back(std::move(old_input_file));
      continue;
    }
    const auto input_file_components = [&] {
      auto input_file_components = GetInputFileComponents(old_input_file);
      if (input_file_components.ok()) {
        // Overwrite the old crash signature with the new one.
        input_file_components->crash_signature =
            batch_result.failure_signature();
        return *std::move(input_file_components);
      }
      // If the input file name is not in the expected format, we'll rename it
      // to the new format using the input signature as the bug ID.
      const std::string input_signature = Hash(old_input);
      return InputFileComponents{
          /*bug_id=*/input_signature,
          /*crash_signature=*/batch_result.failure_signature(),
          /*input_signature=*/input_signature,
      };
    }();
    std::string new_input_file_name = GetInputFileName(
        input_file_components.bug_id, input_file_components.crash_signature,
        input_file_components.input_signature);
    std::string new_input_file =
        std::filesystem::path(crashing_dir) / new_input_file_name;
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
        new_input_file_name = std::filesystem::path(old_input_file).filename();
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
            /*input_signature=*/input_file_components.input_signature,
            /*description=*/batch_result.failure_description(),
            /*input_path=*/new_input_file,
        });
  }
  for (const std::string& old_input_file : irreproducible_input_files) {
    const auto input_file_components = GetInputFileComponents(old_input_file);
    if (!input_file_components.ok()) {
      FUZZTEST_LOG(WARNING)
          << "Failed to get input file components for " << old_input_file
          << ". Status: " << input_file_components.status();
      const auto status =
          RemotePathDelete(old_input_file, /*recursively=*/false);
      if (status.ok()) {
        --crash_and_regression_input_count;
      } else {
        FUZZTEST_LOG(ERROR) << "Failed to delete file " << old_input_file
                            << ". Status: " << status;
      }
      continue;
    }

    auto crash_it =
        reproduced_crashes.find(input_file_components->crash_signature);
    bool is_new_crash = false;
    if (crash_it == reproduced_crashes.end()) {
      auto crash_jt = new_crashes.find(input_file_components->crash_signature);
      if (crash_jt != new_crashes.end()) {
        crash_it = reproduced_crashes.insert(*crash_jt).first;
        is_new_crash = true;
      }
    }
    // Replace only one of the old inputs with a new input per crash signature.
    if (is_new_crash) {
      FUZZTEST_CHECK(crash_it != reproduced_crashes.end());
      const std::string new_input_file_name = GetInputFileName(
          input_file_components->bug_id, input_file_components->crash_signature,
          crash_it->second.input_signature);
      const std::string new_input_file =
          std::filesystem::path(crashing_dir) / new_input_file_name;
      if (new_input_file == old_input_file) {
        // For some reason, the old input couldn't reproduce the crash during
        // reproduction, but it was re-discovered during fuzzing, so it is
        // flaky. We keep the input.
        const auto status = RemotePathTouchExistingFile(new_input_file);
        if (status.ok()) {
          crash_summary.AddCrash({/*id=*/new_input_file_name,
                                  /*category=*/crash_it->second.description,
                                  input_file_components->crash_signature,
                                  crash_it->second.description});
        } else {
          FUZZTEST_LOG(ERROR) << "Failed to touch file " << new_input_file
                              << ". Status: " << status;
        }
      } else {
        const auto status =
            RemotePathDelete(old_input_file, /*recursively=*/false);
        if (status.ok()) {
          --crash_and_regression_input_count;
          const auto status =
              RemoteFileCopy(crash_it->second.input_path, new_input_file);
          if (status.ok()) {
            crash_summary.AddCrash({/*id=*/new_input_file_name,
                                    /*category=*/crash_it->second.description,
                                    input_file_components->crash_signature,
                                    crash_it->second.description});
            ++crash_and_regression_input_count;
          } else {
            FUZZTEST_LOG(ERROR)
                << "Failed to copy file " << crash_it->second.input_path
                << " to " << new_input_file << ". Status: " << status;
            // Remove the input from `reproduced_crashes` since we failed to
            // store it.
            reproduced_crashes.erase(crash_it);
          }
        } else {
          FUZZTEST_LOG(ERROR) << "Failed to delete file " << old_input_file
                              << ". Status: " << status;
          // Remove the input from `reproduced_crashes` since we failed to
          // store it.
          reproduced_crashes.erase(crash_it);
        }
      }
    } else {
      // Not reproducible, move to the regression directory. We explicitly
      // construct the file name from the components to account for old-style
      // file names that consisted only of the input signature.
      const std::string new_input_file_name = GetInputFileName(
          input_file_components->bug_id, input_file_components->crash_signature,
          input_file_components->input_signature);
      const std::string new_input_file =
          std::filesystem::path(regression_dir) / new_input_file_name;
      if (new_input_file != old_input_file) {
        const auto status = RemoteFileRename(old_input_file, new_input_file);
        FUZZTEST_LOG_IF(ERROR, !status.ok())
            << "Failed to rename file " << old_input_file << " to "
            << new_input_file << ". Status: " << status;
      }
    }
  }

  static constexpr int kMaxCrashAndRegressionInputCount = 10;
  for (auto& [crash_signature, details] : new_crashes) {
    if (reproduced_crashes.contains(crash_signature)) continue;
    if (crash_and_regression_input_count >= kMaxCrashAndRegressionInputCount) {
      FUZZTEST_LOG(WARNING)
          << "Reached the maximum number of crash and regression inputs: "
          << kMaxCrashAndRegressionInputCount
          << ". Not storing any new crashes.";
      break;
    }
    const std::string bug_id = Hash(
        absl::StrCat(absl::FormatTime(absl::Now()), details.input_signature));
    const std::string new_input_file_name =
        GetInputFileName(bug_id, crash_signature, details.input_signature);
    const std::string new_input_file =
        std::filesystem::path(crashing_dir) / new_input_file_name;
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
    ++crash_and_regression_input_count;
  }
}

}  // namespace fuzztest::internal
