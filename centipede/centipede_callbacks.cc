// Copyright 2022 The Centipede Authors.
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

#include "./centipede/centipede_callbacks.h"

#include <algorithm>
#include <cstddef>
#include <cstdlib>
#include <filesystem>  // NOLINT
#include <string>
#include <string_view>
#include <system_error>  // NOLINT
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./centipede/binary_info.h"
#include "./centipede/command.h"
#include "./centipede/control_flow.h"
#include "./centipede/defs.h"
#include "./centipede/logging.h"
#include "./centipede/mutation_input.h"
#include "./centipede/runner_request.h"
#include "./centipede/runner_result.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"

namespace centipede {

void CentipedeCallbacks::PopulateBinaryInfo(BinaryInfo &binary_info) {
  binary_info.InitializeFromSanCovBinary(
      env_.coverage_binary, env_.objdump_path, env_.symbolizer_path, temp_dir_);
  // Check the PC table.
  if (binary_info.pc_table.empty()) {
    if (env_.require_pc_table) {
      LOG(ERROR) << "Could not get PC table; exiting (override with "
                    "--require_pc_table=false)";
      exit(EXIT_FAILURE);
    }
    LOG(WARNING) << "Could not get PC table; CF table and debug symbols will "
                    "not be used";
    return;
  }
  // Check CF table.
  if (binary_info.cf_table.empty()) {
    LOG(WARNING)
        << "Could not get CF table; binary should be built with Clang 16 (or "
           "later) and with -fsanitize-coverage=control-flow flag";
  } else {
    // Construct call-graph and cfg using loaded cf_table and pc_table.
    // TODO(b/284044008): These two are currently used only inside
    //  `CoverageFrontier`, so we can mask the bug's failure by conditionally
    //  initilizing them like this.
    if (env_.use_coverage_frontier) {
      binary_info.control_flow_graph.InitializeControlFlowGraph(
          binary_info.cf_table, binary_info.pc_table);
      binary_info.call_graph.InitializeCallGraph(binary_info.cf_table,
                                                 binary_info.pc_table);
    }
  }
}

std::string CentipedeCallbacks::ConstructRunnerFlags(
    std::string_view extra_flags, bool disable_coverage) {
  std::vector<std::string> flags = {
      "CENTIPEDE_RUNNER_FLAGS=",
      absl::StrCat("timeout_per_input=", env_.timeout_per_input),
      absl::StrCat("timeout_per_batch=", env_.timeout_per_batch),
      absl::StrCat("address_space_limit_mb=", env_.address_space_limit_mb),
      absl::StrCat("rss_limit_mb=", env_.rss_limit_mb),
      absl::StrCat("crossover_level=", env_.crossover_level),
  };
  if (!disable_coverage) {
    flags.emplace_back(absl::StrCat("path_level=", env_.path_level));
    if (env_.use_pc_features) flags.emplace_back("use_pc_features");
    if (env_.use_counter_features) flags.emplace_back("use_counter_features");
    if (env_.use_cmp_features) flags.emplace_back("use_cmp_features");
    flags.emplace_back(absl::StrCat("callstack_level=", env_.callstack_level));
    if (env_.use_auto_dictionary) flags.emplace_back("use_auto_dictionary");
    if (env_.use_dataflow_features) flags.emplace_back("use_dataflow_features");
  }
  if (!env_.runner_dl_path_suffix.empty()) {
    flags.emplace_back(
        absl::StrCat("dl_path_suffix=", env_.runner_dl_path_suffix));
  }
  if (!env_.pcs_file_path.empty())
    flags.emplace_back(absl::StrCat("pcs_file_path=", env_.pcs_file_path));
  if (!extra_flags.empty()) flags.emplace_back(extra_flags);
  flags.emplace_back("");
  return absl::StrJoin(flags, ":");
}

Command &CentipedeCallbacks::GetOrCreateCommandForBinary(
    std::string_view binary) {
  for (auto &cmd : commands_) {
    if (cmd.path() == binary) return cmd;
  }
  // We don't want to collect coverage for extra binaries. It won't be used.
  bool disable_coverage =
      std::find(env_.extra_binaries.begin(), env_.extra_binaries.end(),
                binary) != env_.extra_binaries.end();

  std::vector<std::string> env = {ConstructRunnerFlags(
      absl::StrCat(":shmem:arg1=", inputs_blobseq_.path(),
                   ":arg2=", outputs_blobseq_.path(),
                   ":failure_description_path=", failure_description_path_,
                   ":"),
      disable_coverage)};

  if (env_.clang_coverage_binary == binary)
    env.emplace_back(
        absl::StrCat("LLVM_PROFILE_FILE=",
                     WorkDir{env_}.SourceBasedCoverageRawProfilePath()));

  // Allow for the time it takes to fork a subprocess etc.
  const auto amortized_timeout =
      absl::Seconds(env_.timeout_per_batch) + absl::Seconds(5);
  Command &cmd = commands_.emplace_back(Command(
      /*path=*/binary, /*args=*/{},
      /*env=*/env,
      /*out=*/execute_log_path_,
      /*err=*/execute_log_path_,
      /*timeout=*/amortized_timeout,
      /*temp_file_path=*/temp_input_file_path_));
  if (env_.fork_server) cmd.StartForkServer(temp_dir_, Hash(binary));

  return cmd;
}

int CentipedeCallbacks::ExecuteCentipedeSancovBinaryWithShmem(
    std::string_view binary, const std::vector<ByteArray> &inputs,
    BatchResult &batch_result) {
  auto start_time = absl::Now();
  batch_result.ClearAndResize(inputs.size());

  // Reset the blobseqs.
  inputs_blobseq_.Reset();
  outputs_blobseq_.Reset();

  size_t num_inputs_written = 0;

  if (env_.has_input_wildcards) {
    CHECK_EQ(inputs.size(), 1);
    WriteToLocalFile(temp_input_file_path_, inputs[0]);
    num_inputs_written = 1;
  } else {
    // Feed the inputs to inputs_blobseq_.
    num_inputs_written =
        runner_request::RequestExecution(inputs, inputs_blobseq_);
  }

  if (num_inputs_written != inputs.size()) {
    LOG(INFO) << "Wrote " << num_inputs_written << "/" << inputs.size()
              << " inputs; shmem_size_mb might be too small: "
              << env_.shmem_size_mb;
  }

  // Run.
  Command &cmd = GetOrCreateCommandForBinary(binary);
  int retval = cmd.Execute();
  inputs_blobseq_.ReleaseSharedMemory();  // Inputs are already consumed.

  // Get results.
  batch_result.exit_code() = retval;
  CHECK(batch_result.Read(outputs_blobseq_));
  outputs_blobseq_.ReleaseSharedMemory();  // Outputs are already consumed.

  // We may have fewer feature blobs than inputs if
  // * some inputs were not written (i.e. num_inputs_written < inputs.size).
  //   * Logged above.
  // * some outputs were not written because the subprocess died.
  //   * Will be logged by the caller.
  // * some outputs were not written because the outputs_blobseq_ overflown.
  //   * Logged by the following code.
  if (retval == 0 && batch_result.num_outputs_read() != num_inputs_written) {
    LOG(INFO) << "Read " << batch_result.num_outputs_read() << "/"
              << num_inputs_written
              << " outputs; shmem_size_mb might be too small: "
              << env_.shmem_size_mb;
  }

  if (env_.print_runner_log) {
    std::string log_text;
    ReadFromLocalFile(execute_log_path_, log_text);
    for (const auto &log_line :
         absl::StrSplit(absl::StripAsciiWhitespace(log_text), '\n')) {
      LOG(INFO).NoPrefix() << "LOG: " << log_line;
    }
  }

  if (retval != EXIT_SUCCESS) {
    ReadFromLocalFile(execute_log_path_, batch_result.log());
    ReadFromLocalFile(failure_description_path_,
                      batch_result.failure_description());
    // Remove failure_description_ here so that it doesn't stay until another
    // failed execution.
    std::filesystem::remove(failure_description_path_);
  }
  VLOG(1) << __FUNCTION__ << " took " << (absl::Now() - start_time);
  return retval;
}

// See also: DumpSeedsToDir().
bool CentipedeCallbacks::GetSeedsViaExternalBinary(
    std::string_view binary, size_t &num_avail_seeds,
    std::vector<ByteArray> &seeds) {
  const auto output_dir = std::filesystem::path(temp_dir_) / "seed_inputs";
  std::error_code error;
  CHECK(std::filesystem::create_directories(output_dir, error));
  CHECK(!error);

  Command cmd(binary, {},
              {absl::StrCat("CENTIPEDE_RUNNER_FLAGS=:dump_seed_inputs:arg1=",
                            output_dir.string(), ":")},
              /*out=*/execute_log_path_,
              /*err=*/execute_log_path_,
              /*timeout=*/absl::InfiniteDuration(),
              /*temp_file_path=*/temp_input_file_path_);
  const int retval = cmd.Execute();

  std::vector<std::string> seed_input_filenames;
  for (const auto &dir_ent : std::filesystem::directory_iterator(output_dir)) {
    seed_input_filenames.push_back(dir_ent.path().filename());
  }
  std::sort(seed_input_filenames.begin(), seed_input_filenames.end());
  num_avail_seeds = seed_input_filenames.size();

  size_t num_seeds_read;
  for (num_seeds_read = 0; num_seeds_read < seeds.size() &&
                           num_seeds_read < seed_input_filenames.size();
       ++num_seeds_read) {
    ReadFromLocalFile(
        (output_dir / seed_input_filenames[num_seeds_read]).string(),
        seeds[num_seeds_read]);
  }
  seeds.resize(num_seeds_read);
  std::filesystem::remove_all(output_dir);

  return retval == 0;
}

// See also: MutateInputsFromShmem().
bool CentipedeCallbacks::MutateViaExternalBinary(
    std::string_view binary, const std::vector<MutationInputRef> &inputs,
    std::vector<ByteArray> &mutants) {
  CHECK(!env_.has_input_wildcards)
      << "Standalone binary does not support custom mutator";

  auto start_time = absl::Now();
  inputs_blobseq_.Reset();
  outputs_blobseq_.Reset();

  size_t num_inputs_written =
      runner_request::RequestMutation(mutants.size(), inputs, inputs_blobseq_);
  LOG_IF(INFO, num_inputs_written != inputs.size())
      << VV(num_inputs_written) << VV(inputs.size());

  // Execute.
  Command &cmd = GetOrCreateCommandForBinary(binary);
  int retval = cmd.Execute();
  inputs_blobseq_.ReleaseSharedMemory();  // Inputs are already consumed.

  // Read all mutants.
  for (size_t i = 0; i < mutants.size(); ++i) {
    auto blob = outputs_blobseq_.Read();
    if (blob.size == 0) {
      mutants.resize(i);
      break;
    }
    mutants[i].assign(blob.data, blob.data + blob.size);
  }
  outputs_blobseq_.ReleaseSharedMemory();  // Outputs are already consumed.
  VLOG(1) << __FUNCTION__ << " took " << (absl::Now() - start_time);
  return retval == 0;
}

size_t CentipedeCallbacks::LoadDictionary(std::string_view dictionary_path) {
  if (dictionary_path.empty()) return 0;
  // First, try to parse the dictionary as an AFL/libFuzzer dictionary.
  // These dictionaries are in plain text format and thus a Centipede-native
  // dictionary will never be mistaken for an AFL/libFuzzer dictionary.
  std::string text;
  ReadFromLocalFile(dictionary_path, text);
  std::vector<ByteArray> entries;
  if (ParseAFLDictionary(text, entries) && !entries.empty()) {
    env_.use_legacy_default_mutator
        ? byte_array_mutator_.AddToDictionary(entries)
        : fuzztest_mutator_.AddToDictionary(entries);
    LOG(INFO) << "Loaded " << entries.size()
              << " dictionary entries from AFL/libFuzzer dictionary "
              << dictionary_path;
    return entries.size();
  }
  // Didn't parse as plain text. Assume Centipede-native corpus format.
  ByteArray packed_dictionary(text.begin(), text.end());
  std::vector<ByteArray> unpacked_dictionary;
  UnpackBytesFromAppendFile(packed_dictionary, &unpacked_dictionary);
  CHECK(!unpacked_dictionary.empty())
      << "Empty or corrupt dictionary file: " << dictionary_path;
  env_.use_legacy_default_mutator
      ? byte_array_mutator_.AddToDictionary(unpacked_dictionary)
      : fuzztest_mutator_.AddToDictionary(unpacked_dictionary);
  LOG(INFO) << "Loaded " << unpacked_dictionary.size()
            << " dictionary entries from " << dictionary_path;
  return unpacked_dictionary.size();
}

}  // namespace centipede
