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

#include "./centipede/centipede_interface.h"

#include <stdlib.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>  // NOLINT
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>
#include <thread>  // NOLINT(build/c++11)
#include <vector>

#include "absl/base/optimization.h"
#include "absl/log/check.h"
#include "absl/log/log.h"
#include "absl/status/status.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_replace.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "./centipede/analyze_corpora.h"
#include "./centipede/binary_info.h"
#include "./centipede/blob_file.h"
#include "./centipede/centipede.h"
#include "./centipede/centipede_callbacks.h"
#include "./centipede/command.h"
#include "./centipede/corpus_io.h"
#include "./centipede/coverage.h"
#include "./centipede/distill.h"
#include "./centipede/early_exit.h"
#include "./centipede/environment.h"
#include "./centipede/logging.h"  // IWYU pragma: keep
#include "./centipede/minimize_crash.h"
#include "./centipede/pc_info.h"
#include "./centipede/remote_file.h"
#include "./centipede/runner_result.h"
#include "./centipede/stats.h"
#include "./centipede/util.h"
#include "./centipede/workdir.h"
#include "./common/defs.h"
#include "./common/hash.h"
#include "./fuzztest/internal/configuration.h"

namespace centipede {

namespace {

// Sets signal handler for SIGINT and SIGALRM.
void SetSignalHandlers(absl::Time stop_at) {
  for (int signum : {SIGINT, SIGALRM}) {
    struct sigaction sigact = {};
    sigact.sa_handler = [](int received_signum) {
      if (received_signum == SIGINT) {
        ABSL_RAW_LOG(INFO, "Ctrl-C pressed: winding down");
        RequestEarlyExit(EXIT_FAILURE);  // => abnormal outcome
      } else if (received_signum == SIGALRM) {
        ABSL_RAW_LOG(INFO, "Reached --stop_at time: winding down");
        RequestEarlyExit(EXIT_SUCCESS);  // => expected outcome
      } else {
        ABSL_UNREACHABLE();
      }
    };
    sigaction(signum, &sigact, nullptr);
  }

  if (stop_at != absl::InfiniteFuture()) {
    const absl::Duration stop_in = stop_at - absl::Now();
    // Setting an alarm works only if the delay is longer than 1 second.
    if (stop_in >= absl::Seconds(1)) {
      LOG(INFO) << "Setting alarm for --stop_at time " << stop_at << " (in "
                << stop_in << ")";
      PCHECK(alarm(absl::ToInt64Seconds(stop_in)) == 0) << "Alarm already set";
    } else {
      LOG(WARNING) << "Already reached --stop_at time " << stop_at
                   << " upon starting: winding down immediately";
      RequestEarlyExit(EXIT_SUCCESS);  // => expected outcome
    }
  }
}

// Runs env.for_each_blob on every blob extracted from env.args.
// Returns EXIT_SUCCESS on success, EXIT_FAILURE otherwise.
int ForEachBlob(const Environment &env) {
  auto tmpdir = TemporaryLocalDirPath();
  CreateLocalDirRemovedAtExit(tmpdir);
  std::string tmpfile = std::filesystem::path(tmpdir).append("t");

  for (const auto &arg : env.args) {
    LOG(INFO) << "Running '" << env.for_each_blob << "' on " << arg;
    auto blob_reader = DefaultBlobFileReaderFactory();
    absl::Status open_status = blob_reader->Open(arg);
    if (!open_status.ok()) {
      LOG(INFO) << "Failed to open " << arg << ": " << open_status;
      return EXIT_FAILURE;
    }
    ByteSpan blob;
    while (blob_reader->Read(blob) == absl::OkStatus()) {
      ByteArray bytes;
      bytes.insert(bytes.begin(), blob.data(), blob.end());
      // TODO(kcc): [impl] add a variant of WriteToLocalFile that accepts Span.
      WriteToLocalFile(tmpfile, bytes);
      std::string command_line = absl::StrReplaceAll(
          env.for_each_blob, {{"%P", tmpfile}, {"%H", Hash(bytes)}});
      Command cmd(command_line);
      // TODO(kcc): [as-needed] this creates one process per blob.
      // If this flag gets active use, we may want to define special cases,
      // e.g. if for_each_blob=="cp %P /some/where" we can do it in-process.
      cmd.Execute();
      if (EarlyExitRequested()) return ExitCode();
    }
  }
  return EXIT_SUCCESS;
}

// Runs in a dedicated thread, periodically calls PrintExperimentStats
// on `stats_vec` and `envs`.
// Stops when `continue_running` becomes false.
// Exits immediately if --experiment flag is not used.
void ReportStatsThread(const std::atomic<bool> &continue_running,
                       const std::vector<std::atomic<Stats>> &stats_vec,
                       const std::vector<Environment> &envs) {
  CHECK(!envs.empty());

  std::vector<std::unique_ptr<StatsReporter>> reporters;
  reporters.emplace_back(
      std::make_unique<StatsCsvFileAppender>(stats_vec, envs));
  if (!envs.front().experiment.empty() || ABSL_VLOG_IS_ON(1)) {
    reporters.emplace_back(std::make_unique<StatsLogger>(stats_vec, envs));
  }

  // TODO(ussuri): Use constant time increments for CSV generation?
  for (int i = 0; continue_running; ++i) {
    // Sleep at least a few seconds, and at most 600.
    int seconds_to_sleep = std::clamp(i, 5, 600);
    // Sleep(1) in a loop so that we check continue_running once a second.
    while (--seconds_to_sleep && continue_running) {
      absl::SleepFor(absl::Seconds(1));
    }
    for (auto &reporter : reporters) {
      reporter->ReportCurrStats();
    }
  }
}

// Loads corpora from work dirs provided in `env.args`, if there are two args
// provided, analyzes differences. If there is one arg provided, reports the
// function coverage. Returns EXIT_SUCCESS on success, EXIT_FAILURE otherwise.
int Analyze(const Environment &env) {
  LOG(INFO) << "Analyze " << absl::StrJoin(env.args, ",");
  CHECK(!env.binary.empty()) << "--binary must be used";
  if (env.args.size() == 1) {
    const CoverageResults coverage_results =
        GetCoverage(env.binary_name, env.binary_hash, env.args[0]);
    WorkDir workdir{env};
    const std::string coverage_report_path =
        workdir.CoverageReportPath(/*annotation=*/"");
    DumpCoverageReport(coverage_results, coverage_report_path);
  } else if (env.args.size() == 2) {
    AnalyzeCorporaToLog(env.binary_name, env.binary_hash, env.args[0],
                        env.args[1]);
  } else {
    LOG(FATAL) << "for now, --analyze supports only 1 or 2 work dirs; got "
               << env.args.size();
  }
  return EXIT_SUCCESS;
}

void SavePCTableToFile(const PCTable &pc_table, std::string_view file_path) {
  WriteToLocalFile(file_path, AsByteSpan(pc_table));
}

BinaryInfo PopulateBinaryInfoAndSavePCsIfNecessary(
    const Environment &env, CentipedeCallbacksFactory &callbacks_factory,
    std::string &pcs_file_path) {
  BinaryInfo binary_info;
  // Some fuzz targets have coverage not based on instrumenting binaries.
  // For those target, we should not populate binary info.
  if (env.populate_binary_info) {
    ScopedCentipedeCallbacks scoped_callbacks(callbacks_factory, env);
    scoped_callbacks.callbacks()->PopulateBinaryInfo(binary_info);
  }
  if (env.save_binary_info) {
    const std::string binary_info_dir = WorkDir{env}.BinaryInfoDirPath();
    RemoteMkdir(binary_info_dir);
    LOG(INFO) << "Serializing binary info to: " << binary_info_dir;
    binary_info.Write(binary_info_dir);
  }
  if (binary_info.uses_legacy_trace_pc_instrumentation) {
    pcs_file_path = std::filesystem::path(TemporaryLocalDirPath()) / "pcs";
    SavePCTableToFile(binary_info.pc_table, pcs_file_path);
  }
  if (env.use_pcpair_features) {
    CHECK(!binary_info.pc_table.empty())
        << "--use_pcpair_features requires non-empty pc_table";
  }
  return binary_info;
}

int Fuzz(const Environment &env, const BinaryInfo &binary_info,
         std::string_view pcs_file_path,
         CentipedeCallbacksFactory &callbacks_factory) {
  CoverageLogger coverage_logger(binary_info.pc_table, binary_info.symbols);

  std::vector<Environment> envs(env.num_threads, env);
  std::vector<std::atomic<Stats>> stats_vec(env.num_threads);
  std::atomic<bool> stats_thread_continue_running = true;

  std::thread stats_thread(ReportStatsThread,
                           std::ref(stats_thread_continue_running),
                           std::ref(stats_vec), std::ref(envs));

  auto fuzzing_worker = [&](Environment &my_env, std::atomic<Stats> &stats,
                            bool create_tmpdir) {
    if (create_tmpdir) CreateLocalDirRemovedAtExit(TemporaryLocalDirPath());
    my_env.UpdateForExperiment();
    my_env.seed = GetRandomSeed(env.seed);  // uses TID, call in this thread.
    my_env.pcs_file_path = pcs_file_path;   // same for all threads.

    if (env.dry_run) return;

    ScopedCentipedeCallbacks scoped_callbacks(callbacks_factory, my_env);
    Centipede centipede(my_env, *scoped_callbacks.callbacks(), binary_info,
                        coverage_logger, stats);
    centipede.FuzzingLoop();
  };

  if (env.num_threads == 1) {
    // When fuzzing with one thread, run fuzzing loop in the current
    // thread. This is because FuzzTest/Centipede's single-process
    // fuzzing requires the test body, which is invoked by the fuzzing
    // loop, to run in the main thread.
    //
    // Here, the fuzzing worker should not re-create the tmpdir since the path
    // is thread-local and it has been created in the current function.
    fuzzing_worker(envs[0], stats_vec[0], /*create_tmpdir=*/false);
  } else {
    std::vector<std::thread> fuzzing_worker_threads(env.num_threads);
    for (size_t thread_idx = 0; thread_idx < env.num_threads; thread_idx++) {
      Environment &my_env = envs[thread_idx];
      my_env.my_shard_index = env.my_shard_index + thread_idx;
      fuzzing_worker_threads[thread_idx] =
          std::thread(fuzzing_worker, std::ref(my_env),
                      std::ref(stats_vec[thread_idx]), /*create_tmpdir=*/true);
    }
    for (size_t thread_idx = 0; thread_idx < env.num_threads; thread_idx++) {
      fuzzing_worker_threads[thread_idx].join();
    }
  }

  stats_thread_continue_running = false;
  stats_thread.join();

  if (!env.knobs_file.empty()) PrintRewardValues(stats_vec, std::cerr);

  return ExitCode();
}

struct TestShard {
  int index = 0;
  int total_shards = 1;
};

TestShard SetUpTestSharding() {
  TestShard test_shard;
  if (const char *test_total_shards_env = std::getenv("TEST_TOTAL_SHARDS");
      test_total_shards_env != nullptr) {
    CHECK(absl::SimpleAtoi(test_total_shards_env, &test_shard.total_shards))
        << "Failed to parse TEST_TOTAL_SHARDS as an integer: \""
        << test_total_shards_env << "\"";
    CHECK_GT(test_shard.total_shards, 0)
        << "TEST_TOTAL_SHARDS must be greater than 0.";
  }
  if (const char *test_shard_index_env = std::getenv("TEST_SHARD_INDEX");
      test_shard_index_env != nullptr) {
    CHECK(absl::SimpleAtoi(test_shard_index_env, &test_shard.index))
        << "Failed to parse TEST_SHARD_INDEX as an integer: \""
        << test_shard_index_env << "\"";
    CHECK(0 <= test_shard.index && test_shard.index < test_shard.total_shards)
        << "TEST_SHARD_INDEX must be in the range [0, "
        << test_shard.total_shards << ").";
  }
  // Update the shard status file to indicate that we support test sharding.
  // It suffices to update the file's modification time, but we clear the
  // contents for simplicity. This is also what the GoogleTest framework does.
  if (const char *test_shard_status_file =
          std::getenv("TEST_SHARD_STATUS_FILE");
      test_shard_status_file != nullptr) {
    ClearLocalFileContents(test_shard_status_file);
  }

  // Unset the environment variables so they don't affect the child processes.
  CHECK_EQ(unsetenv("TEST_TOTAL_SHARDS"), 0)
      << "Failed to unset TEST_TOTAL_SHARDS: " << std::strerror(errno);
  CHECK_EQ(unsetenv("TEST_SHARD_INDEX"), 0)
      << "Failed to unset TEST_SHARD_INDEX: " << std::strerror(errno);
  CHECK_EQ(unsetenv("TEST_SHARD_STATUS_FILE"), 0)
      << "Failed to unset TEST_SHARD_STATUS_FILE: " << std::strerror(errno);

  return test_shard;
}

int PruneNonreproducibleAndCountRemainingCrashes(
    const Environment &env, absl::Span<const std::string> crashing_input_files,
    CentipedeCallbacksFactory &callbacks_factory) {
  ScopedCentipedeCallbacks scoped_callbacks(callbacks_factory, env);
  BatchResult batch_result;
  int num_remaining_crashes = 0;

  for (const std::string &crashing_input_file : crashing_input_files) {
    ByteArray crashing_input;
    RemoteFileGetContents(crashing_input_file, crashing_input);
    if (scoped_callbacks.callbacks()->Execute(env.binary, {crashing_input},
                                              batch_result)) {
      // The crash is not reproducible.
      RemotePathDelete(crashing_input_file, /*recursively=*/false);
    } else {
      ++num_remaining_crashes;
    }
  }
  return num_remaining_crashes;
}

int UpdateCorpusDatabaseForFuzzTests(
    Environment env, const fuzztest::internal::Configuration &fuzztest_config,
    CentipedeCallbacksFactory &callbacks_factory) {
  LOG(INFO) << "Starting the update of the corpus database for fuzz tests:"
            << "\nBinary: " << env.binary
            << "\nCorpus database: " << fuzztest_config.corpus_database
            << "\nFuzz tests: "
            << absl::StrJoin(fuzztest_config.fuzz_tests, ", ");

  // Step 1: Preliminary set up of test sharding, binary info, etc.
  const auto [test_shard_index, total_test_shards] = SetUpTestSharding();
  const auto corpus_database_path =
      std::filesystem::path(fuzztest_config.corpus_database) /
      fuzztest_config.binary_identifier;
  // The full workdir paths will be formed by appending the fuzz test names to
  // the base workdir path.
  const auto base_workdir_path =
      corpus_database_path / absl::StrFormat("workdir.%03d", test_shard_index);
  // There's no point in saving the binary info to the workdir, since the
  // workdir is deleted at the end.
  env.save_binary_info = false;
  std::string pcs_file_path;
  BinaryInfo binary_info = PopulateBinaryInfoAndSavePCsIfNecessary(
      env, callbacks_factory, pcs_file_path);
  // We limit the number of crash reports until we have crash deduplication.
  env.max_num_crash_reports = 1;

  LOG(INFO) << "Test shard index: " << test_shard_index
            << " Total test shards: " << total_test_shards;

  // Step 2: Are we resuming from a previously terminated run?
  // Find the last index of a fuzz test for which we already have a workdir.
  bool is_resuming = false;
  int resuming_fuzztest_idx = 0;
  for (int i = 0; i < fuzztest_config.fuzz_tests.size(); ++i) {
    if (i % total_test_shards != test_shard_index) continue;
    env.workdir = base_workdir_path / fuzztest_config.fuzz_tests[i];
    // Check the existence of the coverage path to not only make sure the
    // workdir exists, but also that it was created for the same binary as in
    // this run.
    if (RemotePathExists(WorkDir{env}.CoverageDirPath())) {
      is_resuming = true;
      resuming_fuzztest_idx = i;
    }
  }

  LOG_IF(INFO, is_resuming) << "Resuming from the fuzz test "
                            << fuzztest_config.fuzz_tests[resuming_fuzztest_idx]
                            << " (index: " << resuming_fuzztest_idx << ")";

  // Step 3: Iterate over the fuzz tests and run them.
  const std::string binary = env.binary;
  for (int i = resuming_fuzztest_idx; i < fuzztest_config.fuzz_tests.size();
       ++i) {
    if (i % total_test_shards != test_shard_index) continue;
    env.workdir = base_workdir_path / fuzztest_config.fuzz_tests[i];
    if (RemotePathExists(env.workdir) && !is_resuming) {
      // This could be a workdir from a failed run that used a different version
      // of the binary. We delete it so that we don't have to deal with the
      // assumptions under which it is safe to reuse an old workdir.
      RemotePathDelete(env.workdir, /*recursively=*/true);
    }
    is_resuming = false;
    const WorkDir workdir{env};
    RemoteMkdir(workdir.CoverageDirPath());  // Implicitly creates the workdir.
    // TODO: b/338217594 - Call the FuzzTest binary in a flag-agnostic way.
    constexpr std::string_view kFuzzTestFuzzFlag = "--fuzz=";
    env.binary = absl::StrCat(binary, " ", kFuzzTestFuzzFlag,
                              fuzztest_config.fuzz_tests[i]);

    LOG(INFO) << "Fuzzing " << fuzztest_config.fuzz_tests[i]
              << "\n\tTest binary: " << env.binary;

    ClearEarlyExitRequest();
    alarm(absl::ToInt64Seconds(fuzztest_config.time_limit_per_test));
    Fuzz(env, binary_info, pcs_file_path, callbacks_factory);

    // Distill and store the coverage corpus.
    Distill(env);
    const std::filesystem::path fuzztest_db_path =
        corpus_database_path / fuzztest_config.fuzz_tests[i];
    const std::string coverage_dir = fuzztest_db_path / "coverage";
    if (RemotePathExists(coverage_dir)) {
      // In the future, we will store k latest coverage corpora for some k, but
      // for now we only keep the latest one.
      RemotePathDelete(coverage_dir, /*recursively=*/true);
    }
    RemoteMkdir(coverage_dir);
    std::vector<std::string> distilled_corpus_files;
    RemoteGlobMatch(workdir.DistilledCorpusFiles().AllShardsGlob(),
                    distilled_corpus_files);
    ExportCorpus(distilled_corpus_files, coverage_dir);

    const std::filesystem::path crashing_dir = fuzztest_db_path / "crashing";
    const std::vector<std::string> crashing_input_files =
        // The corpus database layout assumes the crash input files are located
        // directly in the crashing subdirectory, so we don't list recursively.
        RemoteListFiles(crashing_dir.c_str(), /*recursively=*/false);
    const int num_remaining_crashes =
        PruneNonreproducibleAndCountRemainingCrashes(env, crashing_input_files,
                                                     callbacks_factory);

    // Before we implement crash deduplication, we only save a single newly
    // found crashing input, and only if there were no previously found crashes.
    if (num_remaining_crashes == 0) {
      const std::vector<std::string> new_crashing_input_files =
          // The crash reproducer directory may contain subdirectories with
          // input files that don't individually cause a crash. We ignore those
          // for now and don't list the files recursively.
          RemoteListFiles(workdir.CrashReproducerDirPath(),
                          /*recursively=*/false);
      if (!new_crashing_input_files.empty()) {
        const std::string crashing_input_file_name =
            std::filesystem::path(new_crashing_input_files[0]).filename();
        RemoteMkdir(crashing_dir.c_str());
        RemotePathRename(new_crashing_input_files[0],
                         (crashing_dir / crashing_input_file_name).c_str());
      }
    }
  }
  RemotePathDelete(base_workdir_path.c_str(), /*recursively=*/true);

  return EXIT_SUCCESS;
}

}  // namespace

int CentipedeMain(const Environment &env,
                  CentipedeCallbacksFactory &callbacks_factory) {
  ClearEarlyExitRequest();
  SetSignalHandlers(env.stop_at);

  if (!env.corpus_to_files.empty()) {
    Centipede::CorpusToFiles(env, env.corpus_to_files);
    return EXIT_SUCCESS;
  }

  if (!env.for_each_blob.empty()) return ForEachBlob(env);

  if (!env.minimize_crash_file_path.empty()) {
    ByteArray crashy_input;
    ReadFromLocalFile(env.minimize_crash_file_path, crashy_input);
    return MinimizeCrash(crashy_input, env, callbacks_factory);
  }

  // Just export the corpus from a local dir and exit.
  if (!env.corpus_from_files.empty()) {
    Centipede::CorpusFromFiles(env, env.corpus_from_files);
    return EXIT_SUCCESS;
  }

  // Export the corpus from a local dir and then fuzz.
  if (!env.corpus_dir.empty()) {
    for (size_t i = 0; i < env.corpus_dir.size(); ++i) {
      const auto &corpus_dir = env.corpus_dir[i];
      if (i > 0 || !env.first_corpus_dir_output_only)
        Centipede::CorpusFromFiles(env, corpus_dir);
    }
  }

  if (env.distill) return Distill(env);

  // Create the local temporary dir once, before creating any threads. The
  // temporary dir must typically exist before `CentipedeCallbacks` can be used.
  const auto tmpdir = TemporaryLocalDirPath();
  CreateLocalDirRemovedAtExit(tmpdir);

  const std::string serialized_target_config = [&] {
    ScopedCentipedeCallbacks scoped_callbacks(callbacks_factory, env);
    return scoped_callbacks.callbacks()->GetSerializedTargetConfig();
  }();
  if (!serialized_target_config.empty()) {
    const auto target_config = fuzztest::internal::Configuration::Deserialize(
        serialized_target_config);
    CHECK_OK(target_config.status())
        << "Failed to deserialize target configuration";
    if (!target_config->corpus_database.empty()) {
      CHECK(target_config->time_limit_per_test < absl::InfiniteDuration())
          << "Updating corpus database requires specifying time limit per fuzz "
             "test.";
      CHECK(target_config->time_limit_per_test >= absl::Seconds(1))
          << "Time limit per fuzz test must be at least 1 second.";
      return UpdateCorpusDatabaseForFuzzTests(env, *target_config,
                                              callbacks_factory);
    }
  }

  // Create the remote coverage dirs once, before creating any threads.
  const auto coverage_dir = WorkDir{env}.CoverageDirPath();
  RemoteMkdir(coverage_dir);
  LOG(INFO) << "Coverage dir: " << coverage_dir
            << "; temporary dir: " << tmpdir;

  std::string pcs_file_path;
  BinaryInfo binary_info = PopulateBinaryInfoAndSavePCsIfNecessary(
      env, callbacks_factory, pcs_file_path);

  if (env.analyze) return Analyze(env);

  return Fuzz(env, binary_info, pcs_file_path, callbacks_factory);
}

}  // namespace centipede
