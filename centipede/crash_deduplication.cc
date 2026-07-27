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
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/clock_interface.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/crash_summary.h"
#include "./centipede/environment.h"
#include "./centipede/runner_result.h"
#include "./centipede/stop.h"
#include "./centipede/workdir.h"
#include "./common/crashing_input_filename.h"
#include "./common/defs.h"
#include "./common/hash.h"
#include "./common/logging.h"
#include "./common/remote_file.h"
#include "./common/status_macros.h"

namespace fuzztest::internal {
namespace {

constexpr size_t kMaxCrashInputCount = 10;

std::string GetInputFileName(std::string_view bug_id,
                             std::string_view crash_signature,
                             std::string_view input_signature) {
  return absl::StrCat(bug_id, "-", crash_signature, "-", input_signature);
}

struct CrashReport {
  CrashDetails details;
  std::string signature;
  std::string bug_id;
};

enum class ActionType {
  kTouch,
  kKeep,
  // Replace the input but keep the bug and signature.
  kReplaceInput,
  // Incubate the input and then replace it.
  kIncubateAndReplaceInput,
  kDelete
};

struct ExistingCrash {
  CrashReport crash_report;
  std::string new_signature;
};

struct IncubatingCrash {
  CrashDetails details;
  std::string new_signature;
};

struct ExistingCrashAction {
  const ExistingCrash& existing_crash;
  ActionType action_type;
  std::optional<CrashDetails> new_details;
};

absl::StatusOr<std::vector<ExistingCrash>> ReadExistingCrashes(
    const std::filesystem::path& crashing_dir) {
  std::vector<ExistingCrash> existing_crashes;
  ASSIGN_OR_RETURN_IF_NOT_OK(
      const std::vector<std::string> input_files,
      RemoteListFiles(crashing_dir.c_str(), /*recursively=*/false));

  existing_crashes.reserve(input_files.size());
  for (const std::string& input_file : input_files) {
    auto input_file_components = ParseCrashingInputFilename(input_file);
    ExistingCrash existing;
    existing.crash_report.details.input_path = input_file;

    if (input_file_components.ok()) {
      existing.crash_report.bug_id = input_file_components->bug_id;
      existing.crash_report.signature = input_file_components->crash_signature;
      existing.crash_report.details.input_signature =
          input_file_components->input_signature;
    } else {
      existing.crash_report.signature = "";
      existing.crash_report.bug_id = "";
    }
    existing_crashes.push_back(std::move(existing));
  }
  return existing_crashes;
}

absl::StatusOr<std::vector<IncubatingCrash>> ReadIncubatingCrashes(
    const std::filesystem::path& incubating_dir) {
  std::vector<IncubatingCrash> incubating_crashes;
  ASSIGN_OR_RETURN_IF_NOT_OK(
      const std::vector<std::string> input_files,
      RemoteListFiles(incubating_dir.c_str(), /*recursively=*/false));

  incubating_crashes.reserve(input_files.size());
  for (const std::string& input_file : input_files) {
    IncubatingCrash incubating;
    incubating.details.input_path = input_file;
    incubating.details.input_signature =
        std::filesystem::path(input_file).filename().c_str();
    incubating_crashes.push_back(std::move(incubating));
  }
  return incubating_crashes;
}

absl::Status ReplayCrash(CentipedeCallbacks& callbacks, const Environment& env,
                         absl::string_view input_path,
                         std::string& out_signature,
                         std::string& out_description) {
  ByteArray input_bytes;
  RETURN_IF_NOT_OK(RemoteFileGetContents(input_path, input_bytes));

  BatchResult batch_result;
  const bool is_reproducible =
      !callbacks.Execute(env.binary, {input_bytes}, batch_result) &&
      batch_result.IsInputFailure();

  if (is_reproducible) {
    out_signature = batch_result.failure_signature();
    out_description = batch_result.failure_description();
  } else {
    out_signature = "";
    out_description = "";
  }
  return absl::OkStatus();
}

absl::Status ReplayExistingCrashes(
    CentipedeCallbacks& callbacks, const Environment& env,
    std::vector<ExistingCrash>& existing_crashes) {
  for (auto& existing : existing_crashes) {
    if (existing.crash_report.signature.empty()) {
      continue;
    }
    RETURN_IF_NOT_OK(ReplayCrash(
        callbacks, env, existing.crash_report.details.input_path,
        existing.new_signature, existing.crash_report.details.description));
  }
  return absl::OkStatus();
}

absl::Status ReplayIncubatingCrashes(
    CentipedeCallbacks& callbacks, const Environment& env,
    std::vector<IncubatingCrash>& incubating_crashes) {
  for (auto& incubating : incubating_crashes) {
    RETURN_IF_NOT_OK(ReplayCrash(callbacks, env, incubating.details.input_path,
                                 incubating.new_signature,
                                 incubating.details.description));
  }
  return absl::OkStatus();
}

absl::flat_hash_map<std::string, CrashDetails> FindNewCrashes(
    const absl::flat_hash_map<std::string, CrashDetails>&
        new_crashes_by_signature,
    absl::Span<const IncubatingCrash> incubating_crashes,
    absl::Span<const ExistingCrash> existing_crashes) {
  absl::flat_hash_map<std::string, CrashDetails> new_crashes;

  // Add new crashes from the current run.
  for (const auto& [signature, details] : new_crashes_by_signature) {
    new_crashes[signature] = details;
  }

  // Add reproducing incubating crashes.
  for (const auto& incubating : incubating_crashes) {
    if (!incubating.new_signature.empty()) {
      new_crashes[incubating.new_signature] = incubating.details;
    }
  }

  // Add reproducing existing crashes (highest priority)
  for (const auto& existing : existing_crashes) {
    if (!existing.new_signature.empty()) {
      new_crashes[existing.new_signature] = existing.crash_report.details;
    }
  }

  return new_crashes;
}

ExistingCrashAction ComputeExistingCrashAction(
    const ExistingCrash& existing,
    const absl::flat_hash_map<std::string, CrashDetails>& new_crashes) {
  const std::string& sig = existing.crash_report.signature;
  const std::string& sig_new = existing.new_signature;

  // If the crash was malformed (no signature), we delete it immediately.
  if (sig.empty()) {
    return {existing, ActionType::kDelete, std::nullopt};
  }

  if (sig == sig_new) {
    return {existing, ActionType::kTouch, std::nullopt};
  }

  // The signature changed or it no longer reproduces.
  auto it = new_crashes.find(sig);
  if (it == new_crashes.end()) {
    // No input reproduces this signature anymore. Keep it on disk (subject to
    // TTL).
    return {existing, ActionType::kKeep, std::nullopt};
  }

  // We have an input for this crash signature.
  if (sig_new.empty()) {
    if (it->second.input_signature ==
        existing.crash_report.details.input_signature) {
      // The crashing input is the same which means that this input is flakey.
      // Just touch it.
      return {existing, ActionType::kTouch, it->second};
    }
    // The old crash did not reproduce at all. Move it to incubating and
    // replace.
    return {existing, ActionType::kIncubateAndReplaceInput, it->second};
  }

  // The old crash reproduced with a different signature. Replace it.
  return {existing, ActionType::kReplaceInput, it->second};
}

std::vector<ExistingCrashAction> ComputeExistingCrashActions(
    absl::Span<const ExistingCrash> existing_crashes,
    const absl::flat_hash_map<std::string, CrashDetails>& new_crashes) {
  std::vector<ExistingCrashAction> actions;
  actions.reserve(existing_crashes.size());
  for (const auto& existing : existing_crashes) {
    actions.push_back(ComputeExistingCrashAction(existing, new_crashes));
  }
  return actions;
}

std::string GenerateBugId(std::string_view input_signature) {
  return Hash(absl::StrCat(absl::FormatTime(absl::Now()), input_signature));
}

absl::Status WriteCrashToFile(const std::filesystem::path& crashing_dir,
                              std::string_view bug_id,
                              std::string_view crash_signature,
                              const CrashDetails& details,
                              CrashSummary& crash_summary) {
  std::string new_input_file_name =
      GetInputFileName(bug_id, crash_signature, details.input_signature);
  std::filesystem::path new_input_path = crashing_dir / new_input_file_name;

  if (details.input_path != new_input_path.c_str()) {
    RETURN_IF_NOT_OK(
        RemoteFileCopy(details.input_path, new_input_path.c_str()));
  }

  crash_summary.AddCrash({/*id=*/new_input_file_name,
                          /*category=*/details.description,
                          std::string(crash_signature), details.description});
  return absl::OkStatus();
}

absl::flat_hash_map<std::string, CrashReport> GenerateNewCrashReports(
    const absl::flat_hash_map<std::string, CrashDetails>& new_crashes,
    absl::Span<const ExistingCrash> existing_crashes) {
  absl::flat_hash_set<std::string> existing_sigs;
  for (const auto& existing : existing_crashes) {
    if (!existing.crash_report.signature.empty()) {
      existing_sigs.insert(existing.crash_report.signature);
    }
  }

  absl::flat_hash_map<std::string, CrashReport> new_crash_reports;
  for (const auto& [signature, details] : new_crashes) {
    if (existing_sigs.contains(signature)) {
      continue;
    }
    std::string bug_id = GenerateBugId(details.input_signature);
    new_crash_reports[signature] = CrashReport{details, signature, bug_id};
  }
  return new_crash_reports;
}

absl::Status TouchCrash(const ExistingCrash& existing,
                        const std::optional<CrashDetails>& new_details,
                        CrashSummary& crash_summary) {
  RETURN_IF_NOT_OK(
      RemotePathTouchExistingFile(existing.crash_report.details.input_path));

  const std::string& description =
      existing.crash_report.details.description.empty() &&
              new_details.has_value()
          ? new_details->description
          : existing.crash_report.details.description;

  crash_summary.AddCrash({
      /*id=*/std::filesystem::path(existing.crash_report.details.input_path)
          .filename()
          .c_str(),
      /*category=*/description,
      existing.crash_report.signature,
      description,
  });
  return absl::OkStatus();
}

absl::Status ExecuteExistingCrashPreservationActions(
    const std::filesystem::path& crashing_dir,
    absl::Span<const ExistingCrashAction> actions,
    CrashSummary& crash_summary) {
  for (const auto& action : actions) {
    const auto& existing = action.existing_crash;

    switch (action.action_type) {
      case ActionType::kTouch:
        RETURN_IF_NOT_OK(
            TouchCrash(existing, action.new_details, crash_summary));
        break;

      case ActionType::kReplaceInput:
      case ActionType::kIncubateAndReplaceInput:
        RETURN_IF_NOT_OK(WriteCrashToFile(crashing_dir,
                                          existing.crash_report.bug_id,
                                          existing.crash_report.signature,
                                          *action.new_details, crash_summary));
        break;

      case ActionType::kKeep:
      case ActionType::kDelete:
        break;
    }
  }
  return absl::OkStatus();
}

absl::Status ExecuteExistingCrashDestructiveActions(
    const std::filesystem::path& incubating_dir,
    absl::Span<const ExistingCrashAction> actions) {
  for (const auto& action : actions) {
    const auto& existing = action.existing_crash;

    switch (action.action_type) {
      case ActionType::kDelete:
      case ActionType::kReplaceInput:
        RETURN_IF_NOT_OK(RemotePathDelete(
            existing.crash_report.details.input_path, /*recursively=*/false));
        break;

      case ActionType::kIncubateAndReplaceInput: {
        std::filesystem::path dest_path =
            incubating_dir / existing.crash_report.details.input_signature;
        RETURN_IF_NOT_OK(RemoteFileRename(
            existing.crash_report.details.input_path, dest_path.c_str()));
        break;
      }

      case ActionType::kKeep:
      case ActionType::kTouch:
        break;
    }
  }
  return absl::OkStatus();
}

absl::Status WriteNewCrashes(
    const std::filesystem::path& crashing_dir,
    const absl::flat_hash_map<std::string, CrashReport>& new_crash_reports,
    size_t num_new_allowed, CrashSummary& crash_summary) {
  size_t new_signatures_written = 0;
  for (const auto& [signature, report] : new_crash_reports) {
    if (new_signatures_written < num_new_allowed) {
      RETURN_IF_NOT_OK(WriteCrashToFile(crashing_dir, report.bug_id,
                                        report.signature, report.details,
                                        crash_summary));
      ++new_signatures_written;
    } else {
      FUZZTEST_LOG(WARNING)
          << "Reached the maximum number of crash inputs: "
          << kMaxCrashInputCount
          << ". Not storing new crash with signature: " << signature;
    }
  }
  return absl::OkStatus();
}

absl::Status CleanUpIncubating(
    const std::filesystem::path& incubating_dir,
    absl::Span<const IncubatingCrash> incubating_crashes) {
  for (const auto& incubating : incubating_crashes) {
    if (!incubating.new_signature.empty()) {
      RETURN_IF_NOT_OK(RemotePathDelete(incubating.details.input_path,
                                        /*recursively=*/false));
    }
  }
  return absl::OkStatus();
}

absl::Status MoveExpiredCrashesToRegression(
    const std::filesystem::path& source_dir,
    const std::filesystem::path& regression_dir, absl::Duration ttl,
    absl::Clock& clock) {
  if (!RemotePathExists(source_dir.c_str())) {
    return absl::OkStatus();
  }
  ASSIGN_OR_RETURN_IF_NOT_OK(
      const std::vector<std::string> active_crash_files,
      RemoteListFiles(source_dir.c_str(), /*recursively=*/false));

  absl::Time now = clock.TimeNow();

  for (const std::string& file_path : active_crash_files) {
    ASSIGN_OR_RETURN_IF_NOT_OK(absl::Time mtime, RemoteFileGetMTime(file_path));

    if (now - mtime > ttl) {
      auto input_file_components = ParseCrashingInputFilename(file_path);
      std::string dest_filename;
      if (input_file_components.ok()) {
        dest_filename = input_file_components->input_signature;
      } else {
        dest_filename = std::filesystem::path(file_path).filename().c_str();
      }

      std::filesystem::path dest_path = regression_dir / dest_filename;
      RETURN_IF_NOT_OK(RemoteFileRename(file_path, dest_path.c_str()));
    }
  }
  return absl::OkStatus();
}

}  // namespace

absl::flat_hash_map<std::string, CrashDetails> GetCrashesFromWorkdir(
    const WorkDir& workdir, size_t total_shards) {
  const bool fail_on_empty_crash_metadata =
      std::getenv("FUZZTEST_FAIL_ON_EMPTY_CRASH_METADATA") != nullptr;
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
      if (crash_signature.empty()) {
        FUZZTEST_LOG_IF(FATAL, fail_on_empty_crash_metadata)
            << "Empty crash signature for " << crashing_input_file_name;
        FUZZTEST_LOG(ERROR)
            << "Ignoring crashing input " << crashing_input_file_name
            << " due to empty crash signature. This is an internal error; "
               "please report it to the FuzzTest team!";
        continue;
      }
      if (crashes.contains(crash_signature)) continue;

      const std::string crash_description_path =
          crash_metadata_dir / absl::StrCat(crashing_input_file_name, ".desc");
      std::string crash_description;
      const absl::Status description_status =
          RemoteFileGetContents(crash_description_path, crash_description);
      if (!description_status.ok()) {
        FUZZTEST_LOG(WARNING)
            << "Ignoring crashing input " << crashing_input_file_name
            << " due to failure to read the crash description: "
            << description_status;
        continue;
      }
      if (crash_description.empty()) {
        FUZZTEST_LOG_IF(FATAL, fail_on_empty_crash_metadata)
            << "Empty crash description for " << crashing_input_file_name;
        FUZZTEST_LOG(ERROR)
            << "Ignoring crashing input " << crashing_input_file_name
            << " due to empty crash description. This is an internal error; "
               "please report it to the FuzzTest team!";
        continue;
      }
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

absl::Status OrganizeCrashingInputs(
    const std::filesystem::path& regression_dir,
    const std::filesystem::path& crashing_dir,
    const std::filesystem::path& incubating_dir, const Environment& env,
    CentipedeCallbacksFactory& callbacks_factory,
    const absl::flat_hash_map<std::string, CrashDetails>&
        new_crashes_by_signature,
    CrashSummary& crash_summary, StopCondition& stop_condition,
    absl::Duration regression_ttl, absl::Clock& clock) {
  RETURN_IF_NOT_OK(RemoteMkdir(crashing_dir.c_str()));
  RETURN_IF_NOT_OK(RemoteMkdir(regression_dir.c_str()));
  RETURN_IF_NOT_OK(RemoteMkdir(incubating_dir.c_str()));

  ASSIGN_OR_RETURN_IF_NOT_OK(auto existing_crashes,
                             ReadExistingCrashes(crashing_dir));
  ASSIGN_OR_RETURN_IF_NOT_OK(auto incubating_crashes,
                             ReadIncubatingCrashes(incubating_dir));

  ScopedCentipedeCallbacks scoped_callbacks(callbacks_factory, env,
                                            stop_condition);
  RETURN_IF_NOT_OK(ReplayExistingCrashes(*scoped_callbacks.callbacks(), env,
                                         existing_crashes));
  RETURN_IF_NOT_OK(ReplayIncubatingCrashes(*scoped_callbacks.callbacks(), env,
                                           incubating_crashes));

  absl::flat_hash_map<std::string, CrashDetails> new_crashes = FindNewCrashes(
      new_crashes_by_signature, incubating_crashes, existing_crashes);

  std::vector<ExistingCrashAction> actions =
      ComputeExistingCrashActions(existing_crashes, new_crashes);

  absl::flat_hash_map<std::string, CrashReport> new_crash_reports =
      GenerateNewCrashReports(new_crashes, existing_crashes);

  RETURN_IF_NOT_OK(ExecuteExistingCrashPreservationActions(
      crashing_dir, actions, crash_summary));

  size_t num_new_allowed = kMaxCrashInputCount > existing_crashes.size()
                               ? kMaxCrashInputCount - existing_crashes.size()
                               : 0;

  RETURN_IF_NOT_OK(WriteNewCrashes(crashing_dir, new_crash_reports,
                                   num_new_allowed, crash_summary));

  RETURN_IF_NOT_OK(
      ExecuteExistingCrashDestructiveActions(incubating_dir, actions));

  RETURN_IF_NOT_OK(CleanUpIncubating(incubating_dir, incubating_crashes));

  RETURN_IF_NOT_OK(MoveExpiredCrashesToRegression(crashing_dir, regression_dir,
                                                  regression_ttl, clock));
  RETURN_IF_NOT_OK(MoveExpiredCrashesToRegression(
      incubating_dir, regression_dir, regression_ttl, clock));

  return absl::OkStatus();
}

}  // namespace fuzztest::internal
