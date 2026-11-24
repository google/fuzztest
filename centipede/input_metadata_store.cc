// Copyright 2026 The Centipede Authors.
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

#include "./centipede/input_metadata_store.h"

#include <algorithm>
#include <cstddef>
#include <filesystem>  // NOLINT
#include <string>
#include <string_view>
#include <vector>

#include "absl/types/span.h"
#include "./centipede/environment.h"
#include "./centipede/runner_result.h"
#include "./common/defs.h"
#include "./common/hash.h"
#include "./common/logging.h"
#include "./common/remote_file.h"

namespace fuzztest::internal {
namespace {

std::string MetadataDir(const Environment& env) {
  if (env.fuzztest_persistent_metadata_root.empty()) return "";
  return (std::filesystem::path(env.fuzztest_persistent_metadata_root) /
          env.fuzztest_binary_identifier / env.test_name)
      .string();
}

std::string MetadataPath(std::string_view dir, ByteSpan input) {
  return (std::filesystem::path(dir) / Hash(input)).string();
}

}  // namespace

InputMetadataStore::InputMetadataStore(const Environment& env)
    : dir_(MetadataDir(env)) {}

std::vector<ByteArray> InputMetadataStore::Load(
    absl::Span<const ByteSpan> inputs) const {
  if (!enabled()) return {};
  std::vector<ByteArray> metadata(inputs.size());
  for (size_t i = 0; i < inputs.size(); ++i) {
    const std::string path = MetadataPath(dir_, inputs[i]);
    if (!RemotePathExists(path)) continue;
    FUZZTEST_CHECK_OK(RemoteFileGetContents(path, metadata[i]))
        << "Failed to read the persistent input metadata from " << path;
  }
  return metadata;
}

void InputMetadataStore::Save(absl::Span<const ByteSpan> inputs,
                              const BatchResult& batch_result) {
  if (!enabled()) return;
  const size_t num_results =
      std::min({inputs.size(), batch_result.num_outputs_read(),
                batch_result.results().size()});
  for (size_t i = 0; i < num_results; ++i) {
    const ByteArray& metadata =
        batch_result.results()[i].metadata().persistent_data;
    if (metadata.empty()) continue;
    if (!dir_created_) {
      FUZZTEST_CHECK_OK(RemoteMkdir(dir_))
          << "Failed to create the persistent input metadata directory "
          << dir_;
      dir_created_ = true;
    }
    const std::string path = MetadataPath(dir_, inputs[i]);
    FUZZTEST_CHECK_OK(RemoteFileSetContents(path, metadata))
        << "Failed to write the persistent input metadata to " << path;
  }
}

}  // namespace fuzztest::internal
