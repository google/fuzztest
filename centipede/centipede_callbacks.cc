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

#include <fcntl.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <filesystem>  // NOLINT
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>  // NOLINT
#include <utility>
#include <vector>

#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/memory/memory.h"
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "./centipede/binary_info.h"
#include "./centipede/command.h"
#include "./centipede/control_flow.h"
#include "./centipede/mutation_input.h"
#include "./centipede/runner_request.h"
#include "./centipede/runner_result.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"
#include "./common/blob_file.h"
#include "./common/defs.h"
#include "./common/hash.h"
#include "./common/logging.h"

namespace fuzztest::internal {

constexpr auto kCommandCleanupTimeout = absl::Seconds(60);
constexpr auto kPollMinimalTimeout = absl::Milliseconds(1);

class CentipedeCallbacks::PersistentModeProps {
 public:
  explicit PersistentModeProps(std::string server_path)
      : server_path_(std::move(server_path)) {
    CHECK(!server_path_.empty());

    server_socket_ = socket(AF_UNIX, SOCK_STREAM, 0);
    PCHECK(server_socket_ != -1);

    SetCloseOnExec(server_socket_);
    SetNonBlocking(server_socket_);

    struct sockaddr_un server_addr{};
    server_addr.sun_family = AF_UNIX;
    if (server_path_.size() > sizeof(server_addr.sun_path) - 1) {
      std::string new_server_path =
          server_path_.substr(0, sizeof(server_addr.sun_path) - 1);
      LOG(WARNING) << "Persistent mode server socket path " << server_path_
                   << " is too long. Truncating it to " << new_server_path;
      server_path_ = std::move(new_server_path);
    }
    strncpy(server_addr.sun_path, server_path_.c_str(),
            sizeof(server_addr.sun_path));

    constexpr int enable = 1;
    PCHECK(setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &enable,
                      sizeof(enable)) != -1);
    PCHECK(bind(server_socket_, (struct sockaddr *)&server_addr,
                sizeof(server_addr)) != -1);

    PCHECK(listen(server_socket_, 1) != -1);
  }

  const std::string &server_path() const { return server_path_; }

  // Triggers the persistent mode to run one request. If the persistent mode
  // finished normally, returns true with `exit_code` set to the return value of
  // the handler (which would be returned as the command exit code if running
  // without persistent mode, hence the name). Returns false otherwise without
  // modifying `exit_code`.
  bool RunOnce(absl::Time deadline, int &exit_code) {
    if (!EnsureConnection(deadline)) {
      return false;
    }
    CHECK_NE(conn_socket_, -1);
    // Kick-off the persistent mode.
    const char req = kPersistentModeRequestRunOnce;
    PCHECK(write(conn_socket_, &req, 1) == 1);
    // Wait for the persistent mode runner to respond.
    int poll_ret = -1;
    struct pollfd poll_fd = {};
    do {
      poll_fd = {
          /*fd=*/conn_socket_,
          /*events=*/POLLIN,
      };
      const int poll_timeout_ms = static_cast<int>(absl::ToInt64Milliseconds(
          std::max(deadline - absl::Now(), kPollMinimalTimeout)));
      poll_ret = poll(&poll_fd, 1, poll_timeout_ms);
    } while (poll_ret < 0 && errno == EINTR);
    if (poll_ret == 1 && (poll_fd.revents & (POLLIN | POLLHUP)) == POLLIN) {
      const int r = read(conn_socket_, &exit_code, sizeof(exit_code));
      if (r == sizeof(exit_code)) return true;
      LOG(ERROR) << "Persistent mode: read() returns " << r
                 << " unexpectedly with revents: " << poll_fd.revents
                 << " errno: " << errno;
    } else if (poll_ret < 0) {
      LOG(ERROR) << "Persistent mode: poll() on connection failed with errno "
                 << errno;
    } else if (poll_ret == 0) {
      LOG(ERROR) << "Persistent mode: poll() on connection timed out";
    }
    Disconnect();
    return false;
  }

  void RequestExit(absl::Time deadline) {
    if (!EnsureConnection(deadline)) return;
    CHECK_NE(conn_socket_, -1);
    const char req = kPersistentModeRequestExit;
    PCHECK(write(conn_socket_, &req, 1) == 1);
    Disconnect();
  }

  ~PersistentModeProps() {
    if (conn_socket_ != -1) {
      Disconnect();
    }

    CHECK_NE(server_socket_, -1);
    PCHECK(close(server_socket_) != -1);
    server_socket_ = -1;

    std::error_code ec;
    CHECK(!server_path_.empty());
    if (!std::filesystem::remove(server_path_, ec)) {
      LOG(ERROR) << "Persistent mode: Failed to remove the server socket file "
                 << server_path_ << ": " << ec.message();
    }
  }

 private:
  static void SetCloseOnExec(int fd) {
    int flags = fcntl(fd, F_GETFD);
    PCHECK(flags != -1);
    flags |= FD_CLOEXEC;
    PCHECK(fcntl(fd, F_SETFD, flags) != -1);
  }

  static void SetNonBlocking(int fd) {
    int flags = fcntl(fd, F_GETFL);
    PCHECK(flags != -1);
    flags |= O_NONBLOCK;
    PCHECK(fcntl(fd, F_SETFL, flags) != -1);
  }

  bool EnsureConnection(absl::Time deadline) {
    if (conn_socket_ != -1) return true;
    // Since the runner always tries to connect to the persistent mode
    // socket at the beginning of the execution, waiting for the connection
    // should be fast if the the runner is able to connect at all. But we
    // need to give enough time for the binary to load and reach the runner
    // logic (60s should be enough).
    deadline = std::min(deadline, absl::Now() + absl::Seconds(60));
    CHECK_NE(server_socket_, -1);
    struct pollfd poll_fd{};
    int poll_ret = -1;
    do {
      poll_fd = {
          /*fd=*/server_socket_,
          /*events=*/POLLIN,
      };
      const int poll_timeout_ms = static_cast<int>(absl::ToInt64Milliseconds(
          std::max(deadline - absl::Now(), kPollMinimalTimeout)));
      poll_ret = poll(&poll_fd, 1, poll_timeout_ms);
    } while (poll_ret < 0 && errno == EINTR);
    if (poll_ret != 1 || (poll_fd.revents & POLLIN) == 0) {
      LOG(ERROR) << "Persistent mode: poll() failed on the server socket "
                 << server_path_;
      return false;
    }
    conn_socket_ = accept(server_socket_, nullptr, 0);
    PCHECK(conn_socket_ != -1);

    SetCloseOnExec(conn_socket_);
    SetNonBlocking(conn_socket_);
    return true;
  }

  void Disconnect() {
    CHECK_NE(conn_socket_, -1);
    PCHECK(close(conn_socket_) != -1);
    conn_socket_ = -1;
  }

  std::string server_path_;
  int server_socket_ = -1;
  int conn_socket_ = -1;
};

namespace {

// When running a test binary in a subprocess, we don't want these environment
// variables to be inherited and affect the execution of the tests.
//
// See list of environment variables here:
// https://bazel.build/reference/test-encyclopedia#initial-conditions
//
// TODO(fniksic): Add end-to-end tests that make sure we don't observe the
// effects of these variables in the test binary.
std::vector<std::string> EnvironmentVariablesToUnset() {
  return {"TEST_DIAGNOSTICS_OUTPUT_DIR",              //
          "TEST_INFRASTRUCTURE_FAILURE_FILE",         //
          "TEST_LOGSPLITTER_OUTPUT_FILE",             //
          "TEST_PREMATURE_EXIT_FILE",                 //
          "TEST_RANDOM_SEED",                         //
          "TEST_RUN_NUMBER",                          //
          "TEST_SHARD_INDEX",                         //
          "TEST_SHARD_STATUS_FILE",                   //
          "TEST_TOTAL_SHARDS",                        //
          "TEST_UNDECLARED_OUTPUTS_ANNOTATIONS_DIR",  //
          "TEST_UNDECLARED_OUTPUTS_DIR",              //
          "TEST_WARNINGS_OUTPUT_FILE",                //
          "GTEST_OUTPUT",                             //
          "XML_OUTPUT_FILE"};
}

}  // namespace

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
      absl::StrCat("stack_limit_kb=", env_.stack_limit_kb),
      absl::StrCat("crossover_level=", env_.crossover_level),
      absl::StrCat("max_len=", env_.max_len),
  };
  if (env_.ignore_timeout_reports) {
    flags.emplace_back("ignore_timeout_reports");
  }
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

CentipedeCallbacks::CommandContext &
CentipedeCallbacks::GetOrCreateCommandContextForBinary(
    std::string_view binary) {
  for (auto &extended_command : extended_commands_) {
    if (extended_command->cmd.path() == binary) return *extended_command;
  }
  // We don't want to collect coverage for extra binaries. It won't be used.
  bool disable_coverage =
      std::find(env_.extra_binaries.begin(), env_.extra_binaries.end(),
                binary) != env_.extra_binaries.end();

  std::unique_ptr<CentipedeCallbacks::PersistentModeProps> persistent_mode;
  if (env_.persistent_mode && !env_.has_input_wildcards) {
    // Cannot be based on temp_dir_, because it can exceed the maximum length of
    // unix socket bind path.
    //
    // The current construction seems to be fine (usually below 100 bytes) for
    // the Linux limit (108 bytes), but we put the descriptive part to the end
    // make it still likely meaningful when truncated.
    std::string server_path =
        absl::StrCat(ProcessAndThreadUniqueID("/tmp/centipede-"), "-",
                     Hash(binary), "-persistent-mode");
    persistent_mode = std::make_unique<CentipedeCallbacks::PersistentModeProps>(
        std::move(server_path));
  }
  std::vector<std::string> env = {ConstructRunnerFlags(
      absl::StrCat(":shmem:test=", env_.test_name, ":arg1=",
                   inputs_blobseq_.path(), ":arg2=", outputs_blobseq_.path(),
                   ":failure_description_path=", failure_description_path_,
                   ":failure_signature_path=", failure_signature_path_,
                   persistent_mode == nullptr
                       ? ""
                       : absl::StrCat(":persistent_mode_socket=",
                                      persistent_mode->server_path()),
                   ":"),
      disable_coverage)};

  if (env_.clang_coverage_binary == binary)
    env.emplace_back(
        absl::StrCat("LLVM_PROFILE_FILE=",
                     WorkDir{env_}.SourceBasedCoverageRawProfilePath()));

  Command::Options cmd_options;
  cmd_options.env_add = std::move(env);
  cmd_options.env_remove = EnvironmentVariablesToUnset();
  cmd_options.stdout_file = execute_log_path_;
  cmd_options.stderr_file = execute_log_path_;
  cmd_options.temp_file_path = temp_input_file_path_;

  CommandContext &extended_command =
      *extended_commands_.emplace_back(absl::WrapUnique(
          new CommandContext{Command{binary, std::move(cmd_options)},
                             std::move(persistent_mode)}));
  if (env_.fork_server)
    extended_command.cmd.StartForkServer(temp_dir_, Hash(binary));

  return extended_command;
}

void CentipedeCallbacks::CleanUpPersistentMode() {
  extended_commands_.erase(
      std::remove_if(
          extended_commands_.begin(), extended_commands_.end(),
          [&](auto &extended_command) {
            if (extended_command->cmd.is_executing() &&
                extended_command->persistent_mode != nullptr) {
              const absl::Time deadline = absl::Now() + kCommandCleanupTimeout;
              extended_command->persistent_mode->RequestExit(deadline);
              const auto ret = extended_command->cmd.Wait(deadline);
              if (!ret.has_value()) {
                LOG(ERROR) << "Timed out while waiting for Command "
                           << extended_command->cmd.path()
                           << " to end from persistent mode.";
              }
              if (!ret.has_value() || env_.print_runner_log) {
                PrintExecutionLog();
              }
              return !ret.has_value();
            }
            return false;
          }),
      extended_commands_.end());
}

int CentipedeCallbacks::RunBatchForBinary(std::string_view binary) {
  auto &extended_command = GetOrCreateCommandContextForBinary(binary);
  auto &cmd = extended_command.cmd;
  const absl::Duration amortized_timeout =
      env_.timeout_per_batch == 0
          ? absl::InfiniteDuration()
          : absl::Seconds(env_.timeout_per_batch) + absl::Seconds(5);
  const auto deadline = absl::Now() + amortized_timeout;
  int exit_code = EXIT_SUCCESS;
  const bool should_clean_up = [&] {
    if (!cmd.is_executing() && !cmd.ExecuteAsync()) {
      return true;
    }
    if (extended_command.persistent_mode != nullptr &&
        extended_command.persistent_mode->RunOnce(deadline, exit_code)) {
      return false;
    }
    const std::optional<int> ret = cmd.Wait(deadline);
    if (!ret.has_value()) return true;
    exit_code = *ret;
    return false;
  }();
  if (should_clean_up) {
    exit_code = [&] {
      if (!cmd.is_executing()) return EXIT_FAILURE;
      LOG(ERROR) << "Cleaning up the batch execution.";
      cmd.RequestStop();
      const auto ret = cmd.Wait(absl::Now() + kCommandCleanupTimeout);
      if (ret.has_value()) return *ret;
      LOG(ERROR) << "Batch execution cleanup failed to end in 60s.";
      return EXIT_FAILURE;
    }();
    extended_commands_.erase(
        std::find_if(extended_commands_.begin(), extended_commands_.end(),
                     [=](const auto &extended_command) {
                       return extended_command->cmd.path() == binary;
                     }));
  }
  return exit_code;
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
    num_inputs_written = RequestExecution(inputs, inputs_blobseq_);
  }

  if (num_inputs_written != inputs.size()) {
    LOG(INFO) << "Wrote " << num_inputs_written << "/" << inputs.size()
              << " inputs; shmem_size_mb might be too small: "
              << env_.shmem_size_mb;
  }

  // Run.
  const int exit_code = RunBatchForBinary(binary);
  inputs_blobseq_.ReleaseSharedMemory();  // Inputs are already consumed.

  // Get results.
  batch_result.exit_code() = exit_code;
  const bool read_success = batch_result.Read(outputs_blobseq_);
  LOG_IF(ERROR, !read_success) << "Failed to read batch result!";
  outputs_blobseq_.ReleaseSharedMemory();  // Outputs are already consumed.

  // We may have fewer feature blobs than inputs if
  // * some inputs were not written (i.e. num_inputs_written < inputs.size).
  //   * Logged above.
  // * some outputs were not written because the subprocess died.
  //   * Will be logged by the caller.
  // * some outputs were not written because the outputs_blobseq_ overflown.
  //   * Logged by the following code.
  if (exit_code == 0 && read_success &&
      batch_result.num_outputs_read() != num_inputs_written) {
    LOG(INFO) << "Read " << batch_result.num_outputs_read() << "/"
              << num_inputs_written
              << " outputs; shmem_size_mb might be too small: "
              << env_.shmem_size_mb;
  }

  if (env_.print_runner_log) PrintExecutionLog();

  if (exit_code != EXIT_SUCCESS) {
    ReadFromLocalFile(execute_log_path_, batch_result.log());
    ReadFromLocalFile(failure_description_path_,
                      batch_result.failure_description());
    if (std::filesystem::exists(failure_signature_path_)) {
      ReadFromLocalFile(failure_signature_path_,
                        batch_result.failure_signature());
    } else {
      // TODO(xinhaoyuan): Refactor runner to use dispatcher so this branch can
      // be removed.
      batch_result.failure_signature() = batch_result.failure_description();
    }
    // Remove the failure description and signature files here so that they do
    // not stay until another failed execution.
    std::filesystem::remove(failure_description_path_);
    std::filesystem::remove(failure_signature_path_);
  }
  VLOG(1) << __FUNCTION__ << " took " << (absl::Now() - start_time);
  return exit_code;
}

CentipedeCallbacks::CommandContext::~CommandContext() = default;

// See also: `DumpSeedsToDir()`.
bool CentipedeCallbacks::GetSeedsViaExternalBinary(
    std::string_view binary, size_t &num_avail_seeds,
    std::vector<ByteArray> &seeds) {
  const auto output_dir = std::filesystem::path{temp_dir_} / "seed_inputs";
  std::error_code error;
  CHECK(std::filesystem::create_directories(output_dir, error));
  CHECK(!error);

  std::string centipede_runner_flags = absl::StrCat(
      "CENTIPEDE_RUNNER_FLAGS=:dump_seed_inputs:test=", env_.test_name,
      ":arg1=", output_dir.string(), ":");
  if (!env_.runner_dl_path_suffix.empty()) {
    absl::StrAppend(&centipede_runner_flags,
                    "dl_path_suffix=", env_.runner_dl_path_suffix, ":");
  }
  Command::Options cmd_options;
  cmd_options.env_add = {std::move(centipede_runner_flags)};
  cmd_options.env_remove = EnvironmentVariablesToUnset();
  cmd_options.stdout_file = execute_log_path_;
  cmd_options.stderr_file = execute_log_path_;
  cmd_options.temp_file_path = temp_input_file_path_;
  Command cmd{binary, std::move(cmd_options)};
  const int retval = cmd.Execute();

  if (env_.print_runner_log) {
    LOG(INFO) << "Getting seeds via external binary returns " << retval;
    PrintExecutionLog();
  }

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

// See also: `DumpSerializedTargetConfigToFile()`.
bool CentipedeCallbacks::GetSerializedTargetConfigViaExternalBinary(
    std::string_view binary, std::string &serialized_config) {
  const auto config_file_path =
      std::filesystem::path{temp_dir_} / "configuration";
  std::string centipede_runner_flags =
      absl::StrCat("CENTIPEDE_RUNNER_FLAGS=:dump_configuration:arg1=",
                   config_file_path.string(), ":");
  if (!env_.runner_dl_path_suffix.empty()) {
    absl::StrAppend(&centipede_runner_flags,
                    "dl_path_suffix=", env_.runner_dl_path_suffix, ":");
  }
  Command::Options cmd_options;
  cmd_options.env_add = {std::move(centipede_runner_flags)};
  cmd_options.env_remove = EnvironmentVariablesToUnset();
  cmd_options.stdout_file = execute_log_path_;
  cmd_options.stderr_file = execute_log_path_;
  cmd_options.temp_file_path = temp_input_file_path_;
  Command cmd{binary, std::move(cmd_options)};
  const bool is_success = cmd.Execute() == 0;

  if (is_success) {
    if (std::filesystem::exists(config_file_path)) {
      ReadFromLocalFile(config_file_path.string(), serialized_config);
    } else {
      serialized_config = "";
    }
  }
  if (env_.print_runner_log || !is_success) {
    PrintExecutionLog();
  }
  std::error_code error;
  std::filesystem::remove(config_file_path, error);
  CHECK(!error);

  return is_success;
}

// See also: MutateInputsFromShmem().
MutationResult CentipedeCallbacks::MutateViaExternalBinary(
    std::string_view binary, const std::vector<MutationInputRef> &inputs,
    size_t num_mutants) {
  CHECK(!env_.has_input_wildcards)
      << "Standalone binary does not support custom mutator";

  auto start_time = absl::Now();
  inputs_blobseq_.Reset();
  outputs_blobseq_.Reset();

  size_t num_inputs_written =
      RequestMutation(num_mutants, inputs, inputs_blobseq_);
  LOG_IF(INFO, num_inputs_written != inputs.size())
      << VV(num_inputs_written) << VV(inputs.size());

  // Execute.
  const int exit_code = RunBatchForBinary(binary);
  inputs_blobseq_.ReleaseSharedMemory();  // Inputs are already consumed.

  if (exit_code != EXIT_SUCCESS) {
    LOG(WARNING) << "Custom mutator failed with exit code: " << exit_code;
  }
  if (env_.print_runner_log || exit_code != EXIT_SUCCESS) {
    PrintExecutionLog();
  }

  MutationResult result;
  result.exit_code() = exit_code;
  result.Read(num_mutants, outputs_blobseq_);
  outputs_blobseq_.ReleaseSharedMemory();  // Outputs are already consumed.

  VLOG(1) << __FUNCTION__ << " took " << (absl::Now() - start_time);
  return result;
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
  // Didn't parse as plain text. Assume encoded corpus format.
  auto reader = DefaultBlobFileReaderFactory();
  CHECK_OK(reader->Open(dictionary_path))
      << "Error in opening dictionary file: " << dictionary_path;
  std::vector<ByteArray> unpacked_dictionary;
  ByteSpan blob;
  while (reader->Read(blob).ok()) {
    unpacked_dictionary.emplace_back(blob.begin(), blob.end());
  }
  CHECK_OK(reader->Close())
      << "Error in closing dictionary file: " << dictionary_path;
  CHECK(!unpacked_dictionary.empty())
      << "Empty or corrupt dictionary file: " << dictionary_path;
  env_.use_legacy_default_mutator
      ? byte_array_mutator_.AddToDictionary(unpacked_dictionary)
      : fuzztest_mutator_.AddToDictionary(unpacked_dictionary);
  LOG(INFO) << "Loaded " << unpacked_dictionary.size()
            << " dictionary entries from " << dictionary_path;
  return unpacked_dictionary.size();
}

void CentipedeCallbacks::PrintExecutionLog() const {
  if (!std::filesystem::exists(execute_log_path_)) {
    LOG(WARNING) << "Log file for the last executed binary does not exist: "
                 << execute_log_path_;
    return;
  }
  std::string log_text;
  ReadFromLocalFile(execute_log_path_, log_text);
  for (const auto &log_line :
       absl::StrSplit(absl::StripAsciiWhitespace(log_text), '\n')) {
    LOG(INFO).NoPrefix() << "LOG: " << log_line;
  }
}

}  // namespace fuzztest::internal
