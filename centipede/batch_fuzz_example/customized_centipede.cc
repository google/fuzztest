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

#include <filesystem>  // NOLINT
#include <string>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "./centipede/command.h"
#include "./centipede/defs.h"
#include "./centipede/environment.h"
#include "./centipede/runner_result.h"
#include "./centipede/shared_memory_blob_sequence.h"
#include "./centipede/util.h"

namespace centipede {
namespace {

bool UpdateBatchResult(absl::string_view output_file,
                       BatchResult& batch_result) {
  ByteArray content;
  ReadFromLocalFile(output_file, content);
  if (content.empty()) {
    LOG(WARNING) << "Skip updating batch result with an empty output file: "
                 << output_file;
    return true;
  }

  BlobSequence blob_seq(content.data(), content.size());
  if (batch_result.Read(blob_seq)) return true;

  LOG(ERROR) << "Failed to read blob sequence from file: " << output_file;
  return false;
}
}  // namespace

bool CustomizedCallbacks::Execute(std::string_view binary,
                                  const std::vector<ByteArray>& inputs,
                                  BatchResult& batch_result) {
  const std::string temp_dir = TemporaryLocalDirPath();
  CHECK(!temp_dir.empty());
  std::filesystem::create_directory(temp_dir);

  std::string input_file_list;
  int index = 0;
  for (const auto& input : inputs) {
    const std::string temp_file_path =
        std::filesystem::path(temp_dir).append(absl::StrCat("input-", index++));
    WriteToLocalFile(temp_file_path, input);
    absl::StrAppend(&input_file_list, temp_file_path);
    absl::StrAppend(&input_file_list, "\n");
  }
  const std::string input_list_filepath =
      std::filesystem::path(temp_dir).append("input_file_list");
  WriteToLocalFile(input_list_filepath, input_file_list);

  const std::string tmp_output_filepath =
      std::filesystem::path(temp_dir).append("output_execution_results");
  const std::string tmp_log_filepath =
      std::filesystem::path(temp_dir).append("tmp_log");

  // Execute.
  Command cmd{env_.binary,
              {input_list_filepath, tmp_output_filepath},
              /*env=*/{ConstructRunnerFlags()},
              tmp_log_filepath,
              tmp_log_filepath};
  const int retval = cmd.Execute();

  std::string tmp_log;
  ReadFromLocalFile(tmp_log_filepath, tmp_log);
  LOG_IF(INFO, !tmp_log.empty()) << tmp_log;

  batch_result.ClearAndResize(inputs.size());
  CHECK(UpdateBatchResult(tmp_output_filepath, batch_result));
  return retval == 0;
}

}  // namespace centipede
