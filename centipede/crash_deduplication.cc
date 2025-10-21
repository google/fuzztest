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
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "./centipede/workdir.h"
#include "./common/logging.h"
#include "./common/remote_file.h"
#include "./common/status_macros.h"

namespace fuzztest::internal {

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

}  // namespace fuzztest::internal
