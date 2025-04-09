// Copyright 2023 The Centipede Authors.
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

#include "./centipede/batch_fuzz_example/customized_centipede.h"

#include <sys/types.h>

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <filesystem>  // NOLINT
#include <string>
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/command.h"
#include "./centipede/environment.h"
#include "./centipede/feature.h"
#include "./centipede/runner_result.h"
#include "./centipede/shared_memory_blob_sequence.h"
#include "./centipede/util.h"
#include "./common/defs.h"
#include "./common/logging.h"

namespace fuzztest::internal {
namespace {

void UpdateFeatures(const ByteArray& content, FeatureVec& features) {
  CHECK_EQ(content.size() % sizeof(feature_t), 0)
      << VV(content.size()) << VV(sizeof(feature_t));
  const size_t features_size = content.size() / sizeof(feature_t);
  features.resize(features_size);
  memcpy(features.data(), content.data(), content.size());
}

void UpdateExecutionResult(ByteArray& content,
                           ExecutionResult& execution_result) {
  BlobSequence blob_seq(content.data(), content.size());
  BatchResult local_batch_result;
  local_batch_result.ClearAndResize(1);
  local_batch_result.Read(blob_seq);
  CHECK_EQ(local_batch_result.results().size(), 1);
  CHECK_EQ(local_batch_result.num_outputs_read(), 1);
  const ExecutionResult& local_execution_result =
      local_batch_result.results()[0];

  execution_result.metadata() = local_execution_result.metadata();
  execution_result.mutable_features() = local_execution_result.features();
}

void UpdateBatchResult(const bool feature_only_feedback,
                       std::string_view output_dir, BatchResult& batch_result) {
  std::vector<std::filesystem::path> entries;
  for (const auto& entry :
       std::filesystem::recursive_directory_iterator(output_dir)) {
    entries.push_back(entry.path());
  }
  CHECK_LE(entries.size(), batch_result.results().size());
  std::sort(entries.begin(), entries.end());

  for (size_t index = 0; index < entries.size(); ++index) {
    ByteArray content;
    ReadFromLocalFile(std::string(entries[index]), content);
    if (content.empty()) {
      LOG(WARNING) << "Skip updating batch result with an empty output file: "
                   << entries[index];
      continue;
    }
    ExecutionResult& execution_result = batch_result.results()[index];
    if (feature_only_feedback) {
      UpdateFeatures(content, execution_result.mutable_features());
    } else {
      UpdateExecutionResult(content, execution_result);
    }
  }
}

void DumpBatchResultStats(const BatchResult& batch_result) {
  size_t num_results_with_features = 0;
  for (const ExecutionResult& result : batch_result.results()) {
    if (!result.features().empty()) ++num_results_with_features;
  }
  LOG(INFO) << "Ratio of inputs with features: " << num_results_with_features
            << "/" << batch_result.results().size();
}

}  // namespace

CustomizedCallbacks::CustomizedCallbacks(const Environment& env,
                                         bool feature_only_feedback)
    : CentipedeCallbacks(env), feature_only_feedback_(feature_only_feedback) {}

bool CustomizedCallbacks::Execute(std::string_view binary,
                                  const std::vector<ByteArray>& inputs,
                                  BatchResult& batch_result) {
  const std::string temp_dir = TemporaryLocalDirPath();
  CreateLocalDirRemovedAtExit(temp_dir);

  std::string input_file_list;
  for (size_t index = 0; index < inputs.size(); ++index) {
    const std::string temp_file_path =
        std::filesystem::path(temp_dir).append(absl::StrCat("input-", index));
    WriteToLocalFile(temp_file_path, inputs[index]);
    absl::StrAppend(&input_file_list, temp_file_path);
    absl::StrAppend(&input_file_list, "\n");
  }
  const std::string input_list_filepath =
      std::filesystem::path(temp_dir).append("input_file_list");
  WriteToLocalFile(input_list_filepath, input_file_list);

  const std::string tmp_output_dir =
      std::filesystem::path(temp_dir).append("output_data");
  std::filesystem::create_directory(tmp_output_dir);
  const std::string tmp_log_filepath =
      std::filesystem::path(temp_dir).append("tmp_log");

  // Loads runner flags from `env_` unless they are explicitly specified through
  // the CENTIPEDE_RUNNER_FLAGS environment variable, as used in shell testing.
  std::vector<std::string> env;
  if (getenv("CENTIPEDE_RUNNER_FLAGS") == nullptr) {
    env = {ConstructRunnerFlags()};
  }

  std::vector<std::string> args = {
      "--input_file",
      input_list_filepath,
      "--output_dir",
      tmp_output_dir,
  };
  if (feature_only_feedback_) {
    args.push_back("--enable_feature_only_feedback");
  }

  // Execute.
  Command::Options cmd_options;
  cmd_options.args = std::move(args);
  cmd_options.env_add = std::move(env);
  cmd_options.stdout_file = tmp_log_filepath;
  cmd_options.stderr_file = tmp_log_filepath;
  Command cmd{env_.binary, std::move(cmd_options)};
  const int retval = cmd.Execute();

  std::string tmp_log;
  ReadFromLocalFile(tmp_log_filepath, tmp_log);
  LOG_IF(INFO, !tmp_log.empty()) << tmp_log;

  batch_result.ClearAndResize(inputs.size());
  UpdateBatchResult(feature_only_feedback_, tmp_output_dir, batch_result);

  DumpBatchResultStats(batch_result);
  return retval == 0;
}

}  // namespace fuzztest::internal
